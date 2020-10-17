package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"net"

	"github.com/joncooperworks/wgrpcd"
)

var (
	wgrpcdAddress      = flag.String("wgrpcd-address", "localhost:15002", "-wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program.")
	clientKeyFilename  = flag.String("client-key", "clientkey.pem", "-client-key is the client SSL key.")
	clientCertFilename = flag.String("client-cert", "clientcert.pem", "-client-cert is the client SSL certificate.")
	caCertFilename     = flag.String("ca-cert", "cacert.pem", "-ca-cert is the CA that server certificates will be signed with.")
	wgDeviceName       = flag.String("wireguard-interface", "wg0", "-wireguard-interface is the name of the wireguard interface.")
)

func init() {
	flag.Parse()
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

	config := &wgrpcd.ClientConfig{
		ClientKeyBytes:  clientKeyBytes,
		ClientCertBytes: clientCertBytes,
		CACertFilename:  *caCertFilename,
		GrpcAddress:     *wgrpcdAddress,
		DeviceName:      *wgDeviceName,
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
