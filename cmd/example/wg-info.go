package main

import (
	"context"
	"flag"
	"log"

	"github.com/joncooperworks/wgrpcd"
)

var (
	wgrpcdAddress = flag.String("wgrpcd-address", "localhost:15002", "-wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program.")
)

func main() {

	client := wgrpcd.Client{
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

	log.Println("Found devices: ", devices)
	peers, err := client.ListPeers(context.Background())
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println(peers)
}
