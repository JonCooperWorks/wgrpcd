package wgrpcd

import (
	"net"
)

// PeerConfigInfo contains all information needed to configure a Wireguard peer.
type PeerConfigInfo struct {
	PrivateKey      string
	PublicKey       string
	AllowedIPs      []net.IPNet
	ServerPublicKey string
}
