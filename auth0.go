package wgrpcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/metadata"
)

// Auth0ClientCredentials returns a grpc.DialOption that adds an OAuth2 client that uses the client credentials flow.
// It is meant to be used with auth0's machine to machine OAuth2.
// It optionally allows a client to specify a subset of scopes to limit privileges.
func Auth0ClientCredentials(ctx context.Context, clientID, clientSecret, tokenURL, audience string, scopes ...string) grpc.DialOption {
	params := url.Values{}
	params.Add("audience", audience)
	config := &clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		EndpointParams: params,
		Scopes:         scopes,
	}
	return grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: config.TokenSource(ctx)})
}

const (
	// JWTs must be signed with RS256.
	signingMethod = "RS256"
)

// auth0JWKEndpoint is a list of auth0JWK from auth0.
type auth0JWKEndpoint struct {
	Keys []auth0JWK `json:"keys"`
}

// auth0JWK is a single JWK from auth0 that the auth0 JWT will be signed with.
type auth0JWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// Auth0 uses auth0's Machine to Machine authentication to secure a wgrpcd instance.
// It validates a client's temporary access token using a user-supplied auth0 public key.
// See https://auth0.com/machine-to-machine for more details.
type Auth0 struct {
	Domain        *url.URL
	APIIdentifier string
	JWKSURL       *url.URL
}

// AuthFunc satisfies the AuthFunc interface so clients can use auth0 M2M with wgrpcd over gRPC.
func (a *Auth0) AuthFunc(md metadata.MD) (*AuthResult, error) {
	if len(md["authorization"]) != 1 {
		return nil, fmt.Errorf("expected JWT in 'authorization' metadata field")
	}

	tokenString := md["authorization"][0]
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok && token.Header["alg"] != signingMethod {
			return nil, fmt.Errorf("unexpected signing method: expected %s, got %v", signingMethod, token.Header["alg"])
		}

		cert, err := a.getPemCert(token)
		if err != nil {
			return nil, err
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	checkAud := claims.VerifyAudience(a.APIIdentifier, false)
	if !checkAud {
		return nil, fmt.Errorf("invalid audience, expected %s, got %v", a.APIIdentifier, claims["aud"])
	}
	// Verify 'iss' claim
	checkIss := claims.VerifyIssuer(a.Domain.String(), false)
	if !checkIss {
		return nil, fmt.Errorf("invalid issuer, expected %v, got %v", a.Domain, claims["iss"])
	}

	// auth0 puts the client's OAuth2 client ID in the sub field.
	clientIdentifier := claims["sub"].(string)

	scopes, _ := claims["scope"].(string)
	permissions := strings.Split(scopes, " ")
	return &AuthResult{
		ClientIdentifier: clientIdentifier,
		Timestamp:        time.Now(),
		Permissions:      permissions,
	}, nil
}

func (a *Auth0) getPemCert(token *jwt.Token) (string, error) {
	var cert string
	resp, err := http.Get(a.JWKSURL.String())
	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = auth0JWKEndpoint{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		return cert, errors.New("unable to find appropriate keys")
	}

	return cert, nil
}
