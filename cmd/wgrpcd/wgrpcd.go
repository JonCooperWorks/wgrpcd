// Package main sets up a gRPC server on a localhost port that can control a local Wireguard instance.
package main

import (
	"flag"
	"log"
	"net"
	"os/user"

	"github.com/joncooperworks/wireguardrpc"
	"github.com/joncooperworks/wireguardrpc/pb"
	"google.golang.org/grpc"
)

var (
	listenPort = flag.String("listen-port", "8080", "-listen-port specifies the localhost port for clients to connect to.")
)

func init() {
	flag.Parse()
}

func main() {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("failed to get current user: %v", err)
	}

	if currentUser.Uid != "0" {
		log.Fatalln("wgrpcd must be run as root.")
	}
	log.Println("wgrpcd 0.0.1")
	log.Println("This software has not been audited and runs as root.\nVulnerabilities in this can compromise your root account.\nDo not run this in production")

	listener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("failed to get listener on %s: %v", *listenPort, err)
	}
	rpcServer := grpc.NewServer()
	pb.RegisterWireguardRPCServer(rpcServer, &wireguardrpc.WireguardRPCServer{})
	log.Println("Attempting to listen on port", *listenPort)
	if err := rpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
