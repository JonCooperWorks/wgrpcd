# Wireguard Controller

[![GoDoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/joncooperworks/wgrpcd)

## Warning
`wgrpcd` has not been audited and is not suitable for production workloads.
It's still under heavy development and is a hobby project to be used with [targetpractice.network](https://targetpractice.network) and other projects I develop in my spare time.
Reach out to me on [Twitter](https://twitter.com/joncooperworks) if you're interested in using `wgrpcd` in production.

## Overview
`wgrpcd` controls a Wireguard instance, exposing operations over a gRPC API.
This process must run with permissions to manipulate Wireguard interfaces and as such is bound to localhost by default, but can be publicly exposed to let an application control `wgrpcd` from a different server.
No matter where it's bound, it must be configured to use [mTLS](https://developers.cloudflare.com/access/service-auth/mtls) with TLSv1.3.
Keep all CA key material in a safe place, like [Azure Key Vault](https://godoc.org/github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault).
This gRPC API is meant to be called by a lower privileged application that can provide services on top of Wireguard that interact with the general internet.
It intentionally exposes minimal functionality to limit the attack surface.
Clients have no good reason to retrieve a private key once it has been created.
They should instead generate a new private key if they ever need a new configuration and revoke the old key.

```
Usage of wgrpcd:
  -auth0
        -auth0 enables OAuth2 authentication of clients using auth0's machine-to-machine auth.
  -auth0-api-identifier string
        -auth0-api-identifier is the API identifier given by auth0 when setting up a machine-to-machine app.
  -auth0-domain string
        -auth0-domain is the domain auth0 gives when setting up a machine-to-machine app.
  -ca-cert string
        -ca-cert is the CA that client certificates will be signed with. (default "cacert.pem")
  -hostname string
        -hostname is the domain name of the Wireguard server.
  -listen-address string
        -listen-address specifies the host:port pair to listen on. (default "localhost:15002")
```

`wgrpcd` doesn't maintain any state to limit attack surface.
This means `wgrpcd` does not:
+ Allocate IP Addresses
+ Set DNS providers for clients
+ Limit access between connected devices
+ Monitor VPN traffic

If you need these, you'll need to build it yourself.
You can look at [wireguardhttps](https://github.com/joncooperworks/wireguardhttps) as an example of how to build some of those things on top of `wgrpcd`.

## API Operations
+ Create peer and get provisioned config (one operation to minimize the time the private key is in memory)
+ Regenerate peer config and revoke old private key 
+ Remove peer and revoke old private key
+ Change wireguard listen port
+ View registered peers

## Authentication
`wgrpcd` uses mTLS to limit access to the gRPC API.
Unencrypted connections will be rejected.
Client certificates must be signed by the Certificate Authority passed with the `-ca-cert` flag.
`wgrpcd` will automatically get a SSL certificate for itself using Let's Encrypt.

### auth0
`wgrcpd` also supports optional OAuth2 using [auth0](https://auth0.com/)'s [Machine to Machine](https://auth0.com/machine-to-machine) offering.
I recommend using it if you will be running `wgrpcd` on a separate host from its client(s).
I use it to put `wgrpcd` clients on Heroku while being able to revoke access and maintain better audit logs of access to `wgrpcd`.
Use the `-auth0` flag to enable OAuth2, and pass your auth0 [Domain and API Identifier](https://auth0.com/docs/get-started/set-up-apis) with the `-auth0-domain` and `-auth0-api-identifier` flags.
Using `wgrpcd` with auth0 makes it easier to revoke compromised client credentials and makes logs more granular.

### Other OAuth2 M2M
`wgrpcd` does not have any dependency on auth0 servers.
It can use any OAuth2 provider that implements [auth0's M2M scheme](https://auth0.com/blog/using-m2m-authorization/).
You can implement this scheme yourself and pass the relevant values using the same flags if you don't want to use auth0.

## Using the API
```wgrpcd``` exposes a gRPC server that controls a Wireguard interfaces.
By default, it listens on ```localhost:15002```.
It can be connected to with any language, but this RPC server is intended to be used by [wireguardhttps](https://github.com/joncooperworks/wireguardhttps).
The protobuf service, requests and responses can be found in [pbdefinitions.proto](https://github.com/JonCooperWorks/wgrpcd/blob/master/pbdefinitions.proto).

This package exports an API client that handles gRPC connections and handles input validation.


There's a [wgrpcd.Client](https://godoc.org/github.com/JonCooperWorks/wgrpcd#Client) that handles loading SSL credentials and performs some input validation before sending it over the wire in [client.go](https://github.com/JonCooperWorks/wgrpcd/blob/master/client.go).

To create a client, pass a [wgrpcd.ClientConfig](https://godoc.org/github.com/JonCooperWorks/wgrpcd#ClientConfig) struct to [wgrpcd.NewClient](https://godoc.org/github.com/JonCooperWorks/wgrpcd#NewClient).

```
// ClientConfig contains all information needed to configure a wgrpcd.Client.
type ClientConfig struct {
	GRPCAddress     string
	ClientCertBytes []byte
	ClientKeyBytes  []byte
	CACertFilename  string
}
```

It's possible to use `wgrpcd` clients with encrypted client keys by encrypting the key before committing it to source control.
At runtime, decrypt the client key before passing its bytes to the `wgrpcd.ClientConfig`.
This makes it possible to do `git push heroku master` with `wgprcd` clients without putting your client credentials in version control.


Go clients of `wgrpcd` should use [wgrpcd.Client](https://godoc.org/github.com/JonCooperWorks/wgrpcd#Client) instead of writing their own client implementations.
If you spot an improvement, please submit a pull request.

There's an example client in [wg-info.go](https://github.com/JonCooperWorks/wgrpcd/blob/master/cmd/example/wg-info.go) that displays all connected Wireguard interfaces.
The client needs to be configured for mTLS with a client certificate, key and CA certificate for validating the server.

```
Usage of wg-info:
  -ca-cert string
        -ca-cert is the CA that server certificates will be signed with. (default "cacert.pem")
  -client-cert string
        -client-cert is the client SSL certificate. (default "clientcert.pem")
  -client-key string
        -client-key is the client SSL key. (default "clientkey.pem")
  -wgrpcd-address string
        -wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program. (default "localhost:15002")
  -wireguard-interface string
        -device name is the name of the wireguard interface. (default "wg0")