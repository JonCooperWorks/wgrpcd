# wgrpcd-move
`wgrpcd-move` is a tool that makes it simple to migrate peers to a new Wireguard server.
Simply pass a source and destination `wgrpcd` server to the tool along with authentication and it will do the rest.
You'll still have to manually migrate your Wireguard config file between servers.


```
Usage of wgrpcd-move:
  -dest-ca-cert string
        -dest-ca-cert is the CA cert used to verify the destination server (default "dst_ca.pem")
  -dest-client-cert string
        -dest-client-cert is used to authenticate to the destination server (default "dest_clientcert.pem")
  -dest-client-key string
        -dest-client-key is used to authenticate to the destination server (default "dest_clientkey.pem")
  -dest-wgrpcd string
        -dest-wgrpcd is the wgrpcd host you'll be moving users to (default "localhost:15002")
  -dst-wg-device string
        -src-wg-device is the name of the Wireguard interface on the destination server (default "wg0")
  -source-ca-cert string
        -source-ca-cert is the CA cert used to verify the source server (default "src_ca.pem")
  -source-client-cert string
        -source-client-cert is used to authenticate to the source server (default "src_clientcert.pem")
  -source-client-key string
        -source-client-key is used to authenticate to the source server (default "src_clientkey.pem")
  -source-wgrpcd string
        -source-wgrpcd is the wgrpcd host you'll be moving users from (default "localhost:15002")
  -src-wg-device string
        -src-wg-device is the name of the Wireguard interface on the source server (default "wg0")
```