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
type AuthProvider func(md metadata.MD) (*AuthResult, error)

// authContextKey is a key for values injected into the context by an Authority's UnaryInterceptor.
type authContextKey string

// AuthResult is the result of authenticating a user.
type AuthResult struct {
	ClientIdentifier string
	Timestamp        time.Time
	Permissions      []string
}

// Authority allows wgrpcd to determine who is sending a request and check with a authorizer if the client is allowed to interact with wgrpcd.
// We delegate validation to the IsAuthenticated function so users can integrate wrpcd with any OAuth2 provider, or even a custom auth scheme.
// We log failed authentication attempts with the error message.
type Authority struct {
	IsAuthenticated func(md metadata.MD) (*AuthResult, error)
	Logger          Logger
}

// UnaryInterceptor ensures a request is authenticated based on its metadata before invoking the server handler.
func (a *Authority) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errUnauthorized
	}

	authResult, err := a.IsAuthenticated(md)
	if err != nil {
		a.Logger.Printf("Error authorizing user: %v", err)
		return nil, errUnauthorized
	}

	if !hasPermission(authResult, info.FullMethod) {
		a.Logger.Printf("Client '%s' does not have permission to access method '%s'", authResult.ClientIdentifier, info.FullMethod)
		return nil, errUnauthorized
	}

	a.Logger.Printf("Successfully authenticated client with identifier '%s' and permissions: %+v", authResult.ClientIdentifier, authResult.Permissions)

	// Insert auth result into the context so handlers can determine which client is performing an action.
	authKey := authContextKey(authKeyName)
	ctx = context.WithValue(ctx, authKey, authResult)
	return handler(ctx, req)
}

func hasPermission(user *AuthResult, handler string) bool {
	for _, permission := range user.Permissions {
		if permission == handler {
			return true
		}
	}

	return false
}
