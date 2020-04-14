package wgrpcd

import (
	"net"
	"net/url"
)

type PeerConfigINI struct {
	PrivateKey string
	PublicKey  string
	DNSs       []net.IP
	AllowedIPs []net.IPNet
	Endpoint   url.URL
	Addresses  []net.IPNet
}
