// Package main sets up a gRPC server on a localhost port that can control a local Wireguard instance.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/joncooperworks/wireguardrpc"
	"google.golang.org/grpc"
)

var (
	listenPort = flag.String("listen-port", "15002", "-listen-port specifies the localhost port for clients to connect to.")
)

func init() {
	flag.Parse()
}

func main() {
	log.Println("wgrpcd 0.0.1")
	log.Println("This software has not been audited and runs as root.\nVulnerabilities in this can compromise your root account.\nDo not run this in production")

	listener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("failed to get listener on %s: %v", *listenPort, err)
	}
	rpcServer := grpc.NewServer()
	wireguardrpc.RegisterWireguardRPCServer(rpcServer, &wireguardrpc.Server{})
	log.Println("Attempting to listen on port", *listenPort)
	if err := rpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
