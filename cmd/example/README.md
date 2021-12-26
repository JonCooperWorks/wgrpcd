```
Usage of wg-info:
  -audience string
        -audience is the auth0 audience
  -ca-cert string
        -ca-cert is the CA that server certificates will be signed with. (default "cacert.pem")
  -client-cert string
        -client-cert is the client SSL certificate. (default "clientcert.pem")
  -client-id string
        -client-id is the oauth2 client id
  -client-key string
        -client-key is the client SSL key. (default "clientkey.pem")
  -client-secret string
        -client-secret is the oauth2 client secret
  -openid-provider string
        -openid-provider specifies the OpenID provider to use. Supported: ('aws', 'auth0')
  -token-url string
        -token-url is the oauth2 client credentials token URL
  -wgrpcd-address string
        -wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program. (default "localhost:15002")
  -wireguard-interface string
        -wireguard-interface is the name of the wireguard interface. (default "wg0")
```