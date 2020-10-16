# Wireguard Controller

[![GoDoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/joncooperworks/wgrpcd)


## Overview
`wgrpcd` controls a Wireguard instance, exposing operations over a gRPC API.
This process must run with permissions to manipulate Wireguard interfaces and as such is bound to localhost by default, but can be publicly exposed to let an application control `wgrpcd` from a different server.
No matter where it's bound, it must be configured to use [mTLS](https://developers.cloudflare.com/access/service-auth/mtls) with TLSv1.3.
Keep all key material in a safe place, like [Azure Key Vault](https://godoc.org/github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault).
This gRPC API is meant to be called by a lower privileged application that can provide services on top of Wireguard that interact with the general internet.
It intentionally exposes minimal functionality to limit the attack surface.
Clients have no good reason to retrieve a private key once it has been created.
They should instead generate a new private key if they ever need a new configuration and revoke the old key.

```
Usage of wgrpcd:
  -ca-cert string
        -ca-cert is the CA that client certificates will be signed with. (default "cacert.pem")
  -listen-address string
        -listen-address specifies the host:port pair to listen on. (default "localhost:15002")
  -server-cert string
        -server-cert is the wgrpcd SSL certificate. (default "servercert.pem")
  -server-key string
        -server-key is the wgrpcd SSL key. (default "serverkey.pem")
```

## API Operations
+ Create peer and get provisioned .conf (one operation to minimize the time the private key is in memory)
+ Regenerate peer .conf and revoke old private key 
+ Remove peer and revoke old private key
+ Change wireguard listen port
+ View registered peers

## Using the API
```wgrpcd``` exposes a gRPC server that controls a Wireguard interfaces.
By default, it listens on ```localhost:15002```.
It can be connected to with any language, but this RPC server is intended to be used by [wireguardhttps](https://github.com/joncooperworks/wireguardhttps).
The protobuf service, requests and responses can be found in [pbdefinitions.proto](https://github.com/JonCooperWorks/wgrpcd/blob/master/pbdefinitions.proto).

This package exports an API client that handles gRPC connections and handles input validation.


There's a `wgrpcd.Client` that handles loading SSL credential input and performs some input validation before sending it over the wire in [client.go](https://github.com/JonCooperWorks/wgrpcd/blob/master/client.go).

To create a client, pass a `wgrpcd.ClientConfig` struct to `wgrpcd.NewConfig`.

```
// ClientConfig contains all information needed to configure a wgrpcd.Client.
type ClientConfig struct {
	GrpcAddress        string
	DeviceName         string
	ClientCertFilename string
	ClientKeyFilename  string
	CACertFilename     string
}
```

Go clients of `wgrpcd` should use this instead of writing their own client implementations.
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