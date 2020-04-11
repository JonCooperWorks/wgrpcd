package main

import (
	"log"
	"net"

	wireguard "github.com/joncooperworks/wireguardrpc"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	for _, peer := range peers {
		log.Println(peer)
	}

	allowedIPs := []net.IPNet{
		*MustParseCIDR("0.0.0.0/0"),
		*MustParseCIDR("::/0"),
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatalln(err.Error())
	}

	peerConfig, err := device.AddNewPeer(allowedIPs, key.PublicKey())
	if err != nil {
		log.Fatalln(err.Error())
	}

	peers, err = device.Peers()
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Before:")
	for _, peer := range peers {
		log.Println(peer)
	}

	key, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatalln(err.Error())
	}
	device.RekeyClient(allowedIPs, peerConfig.PublicKey, key.PublicKey())

	peers, err = device.Peers()
	if err != nil {
		log.Fatalln(err.Error())
	}

	log.Println("After:")
	for _, peer := range peers {
		log.Println(peer)
	}
	peerConfigFile := PeerConfigFile{
		PublicKey:  peerConfig.PublicKey.String(),
		PrivateKey: key.String(),
		AllowedIPs: allowedIPs,
	}

	log.Println(peerConfigFile)
}
