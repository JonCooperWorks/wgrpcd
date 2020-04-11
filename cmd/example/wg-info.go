package main

import (
	"log"
	"net"

	wireguard "github.com/joncooperworks/wireguardrpc"
)

type PeerConfigFile struct {
	PrivateKey string
	PublicKey  string
	AllowedIPs []net.IPNet
}

func MustParseCIDR(address string) *net.IPNet {
	_, net, err := net.ParseCIDR(address)
	if err != nil {
		panic(err)
	}

	return net
}

func main() {

	devices, err := wireguard.Devices()
	if err != nil {
		log.Fatalln(err.Error())
	}

	if len(devices) == 0 {
		log.Fatalln("no wireguard device detected")
	}

	log.Println("Found devices: ", devices)
	device := &wireguard.Wireguard{DeviceName: "wg0"}
	peers, err := device.Peers()
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println(peers)
}
