// Package main sets up a gRPC server on a localhost port that can control a local Wireguard instance.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"github.com/joncooperworks/wgrpcd"
)

var (
	certFilename       = flag.String("cert-filename", "servercert.pem", "-cert-filename server's SSL certificate.")
	keyFilename        = flag.String("key-filename", "serverkey.pem", "-key-filename is the server's SSL key.")
	listenAddress      = flag.String("listen-address", "localhost:15002", "-listen-address specifies the host:port pair to listen on.")
	caCertFilename     = flag.String("ca-cert", "cacert.pem", "-ca-cert is the CA that client certificates will be signed with.")
	auth0Domain        = flag.String("auth0-domain", "", "-auth0-domain is the domain auth0 gives when setting up a machine-to-machine app.")
	auth0APIIdentifier = flag.String("auth0-api-identifier", "", "-auth0-api-identifier is the API identifier given by auth0 when setting up a machine-to-machine app.")
	useAuth0           = flag.Bool("auth0", false, "-auth0 enables OAuth2 authentication of clients using auth0's machine-to-machine auth.")
)

func init() {
	flag.Parse()

	if *useAuth0 {
		if *auth0Domain == "" || *auth0APIIdentifier == "" {
			log.Fatalf("-auth0-domain and -auth0-api-identifier must be set when using auth0.")
		}
	}
}

func main() {
	log.Println("wgrpcd 0.0.0-alpha")
	log.Println("This software has not been audited and runs as root.\nVulnerabilities in this can compromise your root account.\nDo not run this in production")

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		log.Fatalf("failed to get listener on %s: %v", *listenAddress, err)
	}

	defer func() {
		err = listener.Close()
		if err != nil {
			log.Fatalf("Failed to close listener. %s\n", err)
		}
	}()

	// Load the CA certificate
	trustedCert, err := ioutil.ReadFile(*caCertFilename)
	if err != nil {
		log.Fatalf("failed to load trusted certificate: %v", err)
	}

	// Put the CA certificate to certificate pool
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(trustedCert) {
		log.Fatalf("failed to append trusted certificate to certificate pool: %v", err)
	}

	serverCert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
	if err != nil {
		log.Fatal(err)
	}

	// Create the TLS configuration
	// Since this is gRPC, we can enforce TLSv1.3.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	config := &wgrpcd.ServerConfig{
		TLSConfig:      tlsConfig,
		CACertFilename: *caCertFilename,
	}

	if *useAuth0 {
		auth0DomainURL, err := url.Parse(*auth0Domain)
		if err != nil {
			log.Fatalf("invalid auth0 domain: %v", err)
		}

		// The jwksURL is given by {auth0domain}/.well-known/jwks.json
		jwksURL, _ := url.Parse(auth0DomainURL.String())
		jwksURL.Path = ".well-known/jwks.json"

		auth0 := &wgrpcd.Auth0{
			Domain:        auth0DomainURL,
			APIIdentifier: *auth0APIIdentifier,
			JWKSURL:       jwksURL,
		}

		config.AuthProvider = auth0.AuthProvider
	}

	server, err := wgrpcd.NewServer(config)
	if err != nil {
		log.Fatalf("%s\n", err)
	}

	err = server.Serve(listener)
	if err != nil {
		log.Fatalf("Failed to start server. %s\n", err)
	}

	if err != nil {
		log.Fatalf("Failed to start gRPC server. %s.", err)
	}
}

func cacheDir(hostname string) (dir string) {
	dir = filepath.Join(os.TempDir(), "cache-golang-autocert-"+hostname)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		log.Println("Found cache dir:", dir)
		return dir
	}
	if err := os.MkdirAll(dir, 0700); err == nil {
		return dir
	}

	panic("couldnt create cert cache directory")
}
