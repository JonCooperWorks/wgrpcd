package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"net/url"

	"github.com/joncooperworks/wgrpcd"
	"google.golang.org/grpc"
)

var (
	wgrpcdAddress      = flag.String("wgrpcd-address", "localhost:15002", "-wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program.")
	clientKeyFilename  = flag.String("client-key", "clientkey.pem", "-client-key is the client SSL key.")
	clientCertFilename = flag.String("client-cert", "clientcert.pem", "-client-cert is the client SSL certificate.")
	caCertFilename     = flag.String("ca-cert", "cacert.pem", "-ca-cert is the CA that server certificates will be signed with.")
	wgDeviceName       = flag.String("wireguard-interface", "wg0", "-wireguard-interface is the name of the wireguard interface.")
	useOauth2          = flag.Bool("oauth2", false, "-oauth2 allows wg-info to use oauth2")
	clientID           = flag.String("client-id", "", "-client-id is the oauth2 client id")
	clientSecret       = flag.String("client-secret", "", "-client-secret is the oauth2 client secret")
	tokenURL           = flag.String("token-url", "", "-token-url is the oauth2 client credentials token URL")
	audience           = flag.String("audience", "", "-audience is the auth0 audience")
)

func init() {
	flag.Parse()

	if *useOauth2 {
		if *clientID == "" || *clientSecret == "" || *tokenURL == "" {
			log.Fatalf("-client-id, -client-secret, -audience and -token-url are required")
		}

		if _, err := url.Parse(*tokenURL); err != nil {
			log.Fatalf("-token-url must be a valid URL")
		}
	}
}

func main() {
	clientKeyBytes, err := ioutil.ReadFile(*clientKeyFilename)
	if err != nil {
		log.Fatalf("failed to read client key: %v", err)
	}

	clientCertBytes, err := ioutil.ReadFile(*clientCertFilename)
	if err != nil {
		log.Fatalf("failed to read server cert: %v", err)
	}

	var opts []grpc.DialOption
	if *useOauth2 {
		creds := wgrpcd.OAuth2ClientCredentials(context.Background(), *clientID, *clientSecret, *tokenURL, *audience)
		opts = append(opts, creds)
	}

	config := &wgrpcd.ClientConfig{
		ClientKeyBytes:  clientKeyBytes,
		ClientCertBytes: clientCertBytes,
		CACertFilename:  *caCertFilename,
		GRPCAddress:     *wgrpcdAddress,
		Options:         opts,
	}

	client, err := wgrpcd.NewClient(config)
	if err != nil {
		log.Fatalln(err.Error())
	}

	devices, err := client.Devices(context.Background())
	if err != nil {
		log.Fatalln(err.Error())
	}

	if len(devices) == 0 {
		log.Fatalln("no wireguard device detected")
	}

	log.Println("Found", len(devices), "devices:", devices)
	peers, err := client.ListPeers(context.Background(), *wgDeviceName)
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println("Found", len(peers), "peers")
	log.Println(peers)

}
