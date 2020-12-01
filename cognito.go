package wgrpcd

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
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

const (
	claimsUseAccess = "access"
)

// AWSCognitoClientCredentials returns a grpc.DialOption that uses the client credentials flow with AWS Cognito.
// Callers can optionally pass the scopes they want for their client in the initial request to limit a client's privileges.
func AWSCognitoClientCredentials(ctx context.Context, clientID, clientSecret, tokenURL string, scopes ...string) grpc.DialOption {
	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		Scopes:       scopes,
	}
	return grpc.WithPerRPCCredentials(oauth.TokenSource{TokenSource: config.TokenSource(ctx)})
}

// awsJWKEndpoint is a list of auth0JWK from AWS Congnito.
type awsJWKEndpoint struct {
	Keys []awsJWK `json:"keys"`
}

// JSONWebKeys is a single JWK from AWS Cognito that the AWS Cognito JWT will be signed with.
type awsJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// AWSCognito authenticates incoming gRPC requests from AWS Cognito App clients.
type AWSCognito struct {
	Domain        *url.URL
	APIIdentifier string
	JWKSURL       *url.URL
}

// AuthProvider satisfies the AuthProvider interface so clients can use auth0 M2M with wgrpcd over gRPC.
func (a *AWSCognito) AuthProvider(md metadata.MD) (*AuthResult, error) {
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

	tokenUse := claims["token_use"]
	if tokenUse != claimsUseAccess {
		return nil, fmt.Errorf("token_use claim must be 'access', got %s", tokenUse)
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

func (a *AWSCognito) getPemCert(token *jwt.Token) (string, error) {
	var cert string
	resp, err := http.Get(a.JWKSURL.String())
	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := ioutil.ReadAll(resp.Body)
		return cert, errors.New(string(b))
	}

	var jwks = awsJWKEndpoint{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert, err = pemFromJWK(&jwks.Keys[k])
			if err != nil {
				return cert, err
			}
		}
	}

	if cert == "" {
		return cert, fmt.Errorf("key not found: %v", token.Header["kid"])
	}

	return cert, nil
}

func pemFromJWK(jwk *awsJWK) (string, error) {
	var cert string
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return cert, err
	}

	var e int
	if jwk.E == "AQAB" || jwk.E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		return cert, fmt.Errorf("need to deocde e: %v", jwk.E)
	}

	n := new(big.Int).SetBytes(nb)
	pk := &rsa.PublicKey{
		N: n,
		E: e,
	}
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return cert, err
	}

	block := &pem.Block{
		Type:  "BEGIN CERTIFICATE",
		Bytes: der,
	}

	var out bytes.Buffer
	err = pem.Encode(&out, block)
	cert = out.String()
	return cert, err
}
