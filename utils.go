package wgrpcd

import (
	"fmt"
	"net"
)

// IPNetsToStrings converts a list of net.IPNets to CIDR subnet strings.
func IPNetsToStrings(nets []net.IPNet) []string {
	ips := []string{}
	for _, net := range nets {
		ips = append(ips, net.String())
	}
	return ips
}

// StringsToIPNet tries to convert a list of CIDR subnet strings to net.IPNets.
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

// IPsToStrings converts a list of net.IPs to string
func IPsToStrings(ips []net.IP) []string {
	rv := []string{}
	for _, n := range ips {
		rv = append(rv, n.String())
	}

	return rv
}

// StringsToIPs parses a list of strings into net.IPs.
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
