package wgrpcd

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	errorMessage = "invalid token"
)

// AuthProvider validates a token based on some criteria.
// It's meant to allow integration with third party auth providers like Azure AD, AWS Cognito or a custom auth scheme.
// It should return true if a request is authorized and false if it isn't.
// Implementations should only return error if the provider returned an error, such as network failure.
type AuthProvider func(authorization []string) (bool, error)

// Authority allows wgrpcd to determine who is sending a request and check with a authorizer if the client is allowed to interact with wgrpcd.
// A client is either allowed to access wgrpcd or denied: there are no privilege levels.
// We delegate token validation to the IsAuthorized function so users can integrate wrpcd with any OAuth2 provider, or even a custom auth scheme.
type Authority struct {
	IsAuthorized func(authorization []string) (bool, error)
	Logger       *log.Logger
}

// Authorize ensures a valid token exists in the request metadata before invoking the server handler.
func (a *Authority) Authorize(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, errorMessage)
	}

	// The keys within metadata.MD are normalized to lowercase.
	// See: https://godoc.org/google.golang.org/grpc/metadata#New
	isAuthorized, err := a.IsAuthorized(md["authorization"])
	if err != nil {
		a.log(fmt.Sprintf("error validating token: %v", err))
		return nil, status.Errorf(codes.Unauthenticated, errorMessage)
	}

	if !isAuthorized {
		return nil, status.Errorf(codes.Unauthenticated, errorMessage)
	}

	return handler(ctx, req)
}

func (a *Authority) log(format string, args ...interface{}) {
	if a.Logger != nil {
		a.Logger.Printf(format, args...)
	}
}
