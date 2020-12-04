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
	errorMessageUnauthenticated = "unauthenticated"
	authKeyName                 = "auth"
)

var (
	errUnauthorized = status.Errorf(codes.Unauthenticated, errorMessageUnauthenticated)
)

// AuthFunc validates a gRPC request's metadata based on some arbitrary criteria.
// It's meant to allow integration with a custom auth scheme.
// Implementations return error if authentication failed.
type AuthFunc func(md metadata.MD) (*AuthResult, error)

// PermissionFunc determines if an authenticated client is authorized to access a particular gRPC method.
// It takes a list of permissions and the grpc.UnaryServerInfo for the current request.
type PermissionFunc func(permissions []string, info *grpc.UnaryServerInfo) bool

// authContextKey is a key for values injected into the context by an Authority's UnaryInterceptor.
type authContextKey string

// AuthResult is the result of authenticating a user.
type AuthResult struct {
	ClientIdentifier string
	Timestamp        time.Time
	Permissions      []string
}

// Authority allows wgrpcd to determine who is sending a request and check with a authorizer if the client is allowed to interact with wgrpcd.
// We delegate authentication to the IsAuthenticated function so users can integrate wgrpcd with any OAuth2 provider, or even a custom auth scheme.
// The HasPermissions function allows users to define custom behaviour for permission strings.
// By default, the Authority will take the method names as permission strings in the AuthResult.
// See cognito.go for an example.
// We log failed authentication attempts with the error message.
type Authority struct {
	IsAuthenticated func(md metadata.MD) (*AuthResult, error)
	HasPermissions  func(permissions []string, info *grpc.UnaryServerInfo) bool
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

	if a.isAuthorized(authResult, info) {
		a.Logger.Printf("Client '%s' does not have permission to access method '%s'", authResult.ClientIdentifier, info.FullMethod)
		return nil, status.Errorf(codes.PermissionDenied, "client '%s' does not have scope: '%s'", authResult.ClientIdentifier, info.FullMethod)
	}

	a.Logger.Printf("Successfully authenticated client with identifier '%s' and permissions: %+v", authResult.ClientIdentifier, authResult.Permissions)

	// Insert auth result into the context so handlers can determine which client is performing an action.
	authKey := authContextKey(authKeyName)
	ctx = context.WithValue(ctx, authKey, authResult)
	return handler(ctx, req)
}

func (a *Authority) isAuthorized(user *AuthResult, info *grpc.UnaryServerInfo) bool {
	if a.HasPermissions == nil {
		return hasPermissions(user.Permissions, info)
	}
	return a.HasPermissions(user.Permissions, info)
}

func hasPermissions(permissions []string, info *grpc.UnaryServerInfo) bool {
	for _, permission := range permissions {
		if permission == info.FullMethod {
			return true
		}
	}

	return false
}
