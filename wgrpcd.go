// Package wgrpcd contains an opinionated Wireguard VPN controller that accepts connections over gRPC and mTLS with TLSv1.3 and Let's Encrypt.
// It supports optional OAuth2 using auth0 or any OAuth2 provider implementing their OAuth2 M2M flow.
// See https://auth0.com/blog/using-m2m-authorization/ for more information.
// wgrpcd can be used as a library but is meant to be used with its included wgrpcd CLI.
package wgrpcd
