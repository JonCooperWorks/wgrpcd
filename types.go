package wgrpcd

import (
	"net"
)

type PeerConfigInfo struct {
	PrivateKey      string
	PublicKey       string
	AllowedIPs      []net.IPNet
	ServerPublicKey string
}
