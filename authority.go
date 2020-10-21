package wgrpcd

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	errorMessage = "unauthorized"
	authKeyName  = "auth"
)

var (
	errUnauthorized = status.Errorf(codes.Unauthenticated, errorMessage)
)

// AuthProvider validates a gRPC request's metadata based on some arbitrary criteria.
// It's meant to allow integration with a custom auth scheme.
// Implementations return error if authentication failed.
// It will be logged if a log.Logger is passed to the Authority.
type AuthProvider func(md metadata.MD) (*AuthResult, error)

// authContextKey is a key for values injected into the context by an Authority's UnaryInterceptor.
type authContextKey string

// AuthResult is the result of authenticating a user.
type AuthResult struct {
	ClientIdentifier string
	Timestamp        time.Time
}

// Authority allows wgrpcd to determine who is sending a request and check with a authorizer if the client is allowed to interact with wgrpcd.
// A client is either allowed to access wgrpcd or denied: there are no privilege levels.
// We delegate validation to the IsAuthorized function so users can integrate wrpcd with any OAuth2 provider, or even a custom auth scheme.
// We log failed authentication attempts with the error message if the Authority has a non-nil log.Logger.
type Authority struct {
	IsAuthorized func(md metadata.MD) (*AuthResult, error)
	Logger       Logger
}

// UnaryInterceptor ensures a request is authenticated based on its metadata before invoking the server handler.
func (a *Authority) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errUnauthorized
	}

	authResult, err := a.IsAuthorized(md)
	if err != nil {
		a.Logger.Printf("Error authorizing user: %v", err)
		return nil, errUnauthorized
	}

	a.Logger.Printf("Successfully authenticated client with identifier '%s'", authResult.ClientIdentifier)

	// Insert auth result into the context so handlers can determine which client is performing an action.
	authKey := authContextKey(authKeyName)
	ctx = context.WithValue(ctx, authKey, authResult)
	return handler(ctx, req)
}
