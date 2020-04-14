package wireguardrpc

import (
	"net"
)

func IPNetsToStrings(nets []net.IPNet) []string {
	ips := []string{}
	for _, net := range nets {
		ips = append(ips, net.String())
	}
	return ips
}

func StringsToIPNet(cidrStrings []string) ([]net.IPNet, error) {
	ipNets := []net.IPNet{}
	for _, cidr := range cidrStrings {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		ipNets = append(ipNets, *ipNet)
	}
	return ipNets, nil
}
