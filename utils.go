package wgrpcd

import (
	"fmt"
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

func IPsToStrings(ips []net.IP) []string {
	rv := []string{}
	for _, n := range ips {
		rv = append(rv, n.String())
	}

	return rv
}

func StringsToIPs(rawIPs []string) ([]net.IP, error) {
	ips := []net.IP{}
	for _, rawIP := range rawIPs {
		ip := net.ParseIP(rawIP)
		if ip == nil {
			return []net.IP{}, fmt.Errorf("%v is not a valid IP address", ip)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}
