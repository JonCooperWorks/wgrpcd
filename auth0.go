package wgrpcd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc/metadata"
)

const (
	// JWTs must be signed with RS256.
	signingMethod = "RS256"
)

// Jwks is a list of JSONWebKeys from auth0.
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys is a single JWK from auth0 that the auth0 JWT will be signed with.
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// PermissionsClaims holds the permissions in the JWT token scope.
type PermissionsClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

// Auth0 uses auth0's Machine to Machine authentication to secure a wgrpcd instance.
// It validates a client's temporary access token using a user-supplied auth0 public key.
// See https://auth0.com/machine-to-machine for more details.
type Auth0 struct {
	Domain        *url.URL
	APIIdentifier string
	JWKSURL       *url.URL
}

// AuthProvider satisfies the AuthProvider interface so clients can use auth0 M2M with wgrpcd over gRPC.
func (a *Auth0) AuthProvider(md metadata.MD) (*AuthResult, error) {
	if len(md["authorization"]) != 1 {
		return nil, fmt.Errorf("expected JWT in 'authorization' metadata field")
	}

	tokenString := md["authorization"][0]
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok && token.Header["alg"] != signingMethod {
			return nil, fmt.Errorf("unexpected signing method: expected %s, got %v", signingMethod, token.Header["alg"])
		}

		claims := token.Claims.(jwt.MapClaims)
		checkAud := claims.VerifyAudience(a.APIIdentifier, false)
		if !checkAud {
			return token, fmt.Errorf("invalid audience, expected %s, got %v", a.APIIdentifier, claims["aud"])
		}
		// Verify 'iss' claim
		checkIss := claims.VerifyIssuer(a.Domain.String(), false)
		if !checkIss {
			return token, fmt.Errorf("invalid issuer, expected %v, got %v", a.Domain, claims["iss"])
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

	claims := token.Claims.(jwt.MapClaims)

	// auth0 puts the client's OAuth2 client ID in the sub field.
	clientIdentifier := claims["sub"].(string)

	scopeClaims, ok := token.Claims.(*PermissionsClaims)
	if !ok {
		return nil, fmt.Errorf("expected scope")
	}

	permissions := strings.Split(scopeClaims.Scope, " ")
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

	var jwks = Jwks{}
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
