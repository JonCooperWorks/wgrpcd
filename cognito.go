package wgrpcd

import (
	"context"
	"net/url"

	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/oauth"
)

// AWSCognitoClientCredentials returns a grpc.DialOption that uses the client credentials flow with AWS Cognito.
func AWSCognitoClientCredentials(ctx context.Context, clientID, clientSecret, tokenURL string, scopes ...string) grpc.DialOption {
	params := url.Values{}
	config := &clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		EndpointParams: params,
		Scopes:         scopes,
	}
	return grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: config.TokenSource(ctx)})
}

// AWSCognito authenticates incoming gRPC requests for AWS Cognito App clients.
type AWSCognito struct {
	Domain        *url.URL
	APIIdentifier string
	JWKSURL       *url.URL
}
