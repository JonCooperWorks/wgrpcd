// Package main sets up a gRPC server on a localhost port that can control a local Wireguard instance.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/joncooperworks/wgrpcd"
)

var (
	listenAddress      = flag.String("listen-address", "localhost:15002", "-listen-address specifies the host:port pair to listen on.")
	serverKeyFilename  = flag.String("server-key", "serverkey.pem", "-server-key is the wgrpcd SSL key.")
	serverCertFilename = flag.String("server-cert", "servercert.pem", "-server-cert is the wgrpcd SSL certificate.")
	caCertFilename     = flag.String("ca-cert", "cacert.pem", "-ca-cert is the CA that client certificates will be signed with.")
)

func init() {
	flag.Parse()
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

	config := &wgrpcd.ServerConfig{
		ServerKeyFilename:  *serverKeyFilename,
		ServerCertFilename: *serverCertFilename,
		CACertFilename:     *caCertFilename,
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
