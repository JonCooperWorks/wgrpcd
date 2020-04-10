# Wireguard Controller

## Overview
Control a Wireguard instance, exposing operations over a gRPC API.
This process must run as root to manipulate Wireguard configuration and should never be exposed on a publicly accessible interface.
To prevent accidental binding to publicly accessible interfaces, only the listening port can be configured.
This gRPC API is meant to be called by a lower privileged application that can provide services on top of Wireguard that interact with the general internet.
It intentionally exposes minimal functionality to limit the attack surface.
Clients have no good reason to retrieve a private key once it has been created.
They should instead generate a new private key if they ever need a new configuration and revoke the old key.

## API Operations
+ Create peer and get provisioned .conf (one operation to minimize the time the private key is in memory)
+ Regenerate peer .conf and revoke old private key 
+ Remove peer and revoke old private key
+ Change wireguard listen port
+ View registered peers

### TODO
+ HTTP RPC API in development, gRPC API in production