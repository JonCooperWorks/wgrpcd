package main

import (
	"context"
	"flag"
	"log"
	"net"

	"github.com/joncooperworks/wgrpcd"
)

var (
	wgrpcdAddress = flag.String("wgrpcd-address", "localhost:15002", "-wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program.")
)

func init() {
	flag.Parse()
}

func main() {

	client := &wgrpcd.GRPCClient{
		GrpcAddress: *wgrpcdAddress,
		DeviceName:  "wg0",
	}
	devices, err := client.Devices(context.Background())
	if err != nil {
		log.Fatalln(err.Error())
	}

	if len(devices) == 0 {
		log.Fatalln("no wireguard device detected")
	}

	log.Println("Found", len(devices), "devices:", devices)
	peers, err := client.ListPeers(context.Background())
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println("Found", len(peers), "peers")
	log.Println(peers)

	_, network, _ := net.ParseCIDR("10.0.0.3/32")
	credentials, err := client.CreatePeer(context.Background(), []net.IPNet{*network})
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println(credentials)

	peers, err = client.ListPeers(context.Background())
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println("Found", len(peers), "peers")
	log.Println(peers)

}
