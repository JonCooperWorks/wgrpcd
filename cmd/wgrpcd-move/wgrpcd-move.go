package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"

	"github.com/joncooperworks/wgrpcd"
	"google.golang.org/grpc"
)

var (
	srcWgrpcd     = flag.String("source-wgrpcd", "localhost:15002", "-source-wgrpcd is the wgrpcd host you'll be moving users from")
	dstWgrpcd     = flag.String("dest-wgrpcd", "localhost:15002", "-dest-wgrpcd is the wgrpcd host you'll be moving users to")
	srcCaCert     = flag.String("source-ca-cert", "src_ca.pem", "-source-ca-cert is the CA cert used to verify the source server")
	dstCaCert     = flag.String("dest-ca-cert", "dst_ca.pem", "-dest-ca-cert is the CA cert used to verify the destination server")
	srcClientKey  = flag.String("source-client-key", "src_clientkey.pem", "-source-client-key is used to authenticate to the source server")
	srcClientCert = flag.String("source-client-cert", "src_clientcert.pem", "-source-client-cert is used to authenticate to the source server")
	dstClientKey  = flag.String("dest-client-key", "dest_clientkey.pem", "-dest-client-key is used to authenticate to the destination server")
	dstClientCert = flag.String("dest-client-cert", "dest_clientcert.pem", "-dest-client-cert is used to authenticate to the destination server")
	srcWgDevice   = flag.String("src-wg-device", "wg0", "-src-wg-device is the name of the Wireguard interface on the source server")
	dstWgDevice   = flag.String("dst-wg-device", "wg0", "-src-wg-device is the name of the Wireguard interface on the destination server")
)

func main() {
	flag.Parse()

	srcKeyBytes, err := ioutil.ReadFile(*srcClientKey)
	if err != nil {
		log.Fatalf("failed to read client key: %v", err)
	}

	srcCertBytes, err := ioutil.ReadFile(*srcClientCert)
	if err != nil {
		log.Fatalf("failed to read server cert: %v", err)
	}

	var opts []grpc.DialOption
	srcConfig := &wgrpcd.ClientConfig{
		ClientKeyBytes:  srcKeyBytes,
		ClientCertBytes: srcCertBytes,
		CACertFilename:  *srcCaCert,
		GRPCAddress:     *srcWgrpcd,
		Options:         opts,
	}

	dstKeyBytes, err := ioutil.ReadFile(*dstClientKey)
	if err != nil {
		log.Fatalf("failed to read client key: %v", err)
	}

	dstCertBytes, err := ioutil.ReadFile(*dstClientCert)
	if err != nil {
		log.Fatalf("failed to read server cert: %v", err)
	}

	dstConfig := &wgrpcd.ClientConfig{
		ClientKeyBytes:  dstKeyBytes,
		ClientCertBytes: dstCertBytes,
		CACertFilename:  *dstCaCert,
		GRPCAddress:     *dstWgrpcd,
		Options:         opts,
	}

	src, err := wgrpcd.NewClient(srcConfig)
	if err != nil {
		log.Fatalln(err.Error())
	}

	dst, err := wgrpcd.NewClient(dstConfig)
	if err != nil {
		log.Fatalln(err.Error())
	}

	err = src.Connect()
	if err != nil {
		log.Fatalln(err.Error())
	}

	err = dst.Connect()
	if err != nil {
		log.Fatalln(err.Error())
	}

	defer src.Close()
	defer dst.Close()

	log.Println("Downloading peers from", *srcWgrpcd)
	peers, err := src.ListPeers(context.Background(), *srcWgDevice)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Found peers:", peers)

	var imports []*wgrpcd.ImportedPeer
	for _, peer := range peers {
		toImport := &wgrpcd.ImportedPeer{
			PublicKey: peer.PublicKey,
			AllowedIPs: peer.AllowedIPs,
		}
		imports = append(imports, toImport)
	}

	log.Println("Importing peers to", *dstWgrpcd)
	err = dst.ImportPeers(context.Background(), *dstWgDevice, imports)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Println("Peers imported to", *dstWgrpcd)
}
