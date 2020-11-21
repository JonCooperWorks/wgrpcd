package wgrpcd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/dgrijalva/jwt-go"
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

func getPemCert(jwksURL *url.URL, token *jwt.Token) (string, error) {
	var cert string
	resp, err := http.Get(jwksURL.String())
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
