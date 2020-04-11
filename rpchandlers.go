package wireguardrpc

import (
	"context"
	"fmt"
	"net"

	"github.com/joncooperworks/wireguardrpc/pb"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	MaxPort = 65535
)

var (
	ErrInvalidPort = fmt.Errorf("Port must be between 0 and %d", MaxPort)
)

type WireguardRPCServer struct {
	pb.UnimplementedWireguardRPCServer
}

func (w *WireguardRPCServer) CreatePeer(ctx context.Context, request *pb.CreatePeerRequest) (*pb.CreatePeerResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	allowedIPs, err := stringsToIPNet(request.GetAllowedIPs())
	if err != nil {
		return nil, err
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	peerConfig, err := wireguard.AddNewPeer(allowedIPs, key.PublicKey())
	if err != nil {
		return nil, err
	}

	response := &pb.CreatePeerResponse{
		PublicKey:  peerConfig.PublicKey.String(),
		PrivateKey: key.String(),
		AllowedIPs: ipsToString(allowedIPs),
	}
	return response, nil
}

func (w *WireguardRPCServer) RekeyPeer(ctx context.Context, request *pb.RekeyPeerRequest) (*pb.RekeyPeerResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	allowedIPs, err := stringsToIPNet(request.GetAllowedIPs())
	if err != nil {
		return nil, err
	}

	publicKey, err := wgtypes.ParseKey(request.GetPublicKey())
	if err != nil {
		return nil, err
	}
	peerConfig, err := wireguard.RekeyClient(allowedIPs, publicKey, key.PublicKey())
	if err != nil {
		return nil, err
	}

	response := &pb.RekeyPeerResponse{
		PublicKey:  peerConfig.PublicKey.String(),
		PrivateKey: key.String(),
		AllowedIPs: ipsToString(allowedIPs),
	}
	return response, nil
}

func (w *WireguardRPCServer) RemovePeer(ctx context.Context, request *pb.RemovePeerRequest) (*pb.RemovePeerResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	publicKey, err := wgtypes.ParseKey(request.GetPublicKey())
	if err != nil {
		return nil, err
	}
	err = wireguard.RemovePeer(publicKey)
	if err != nil {
		return nil, err
	}

	response := &pb.RemovePeerResponse{
		Removed: true,
	}
	return response, nil
}

func (w *WireguardRPCServer) ListPeers(ctx context.Context, request *pb.ListPeersRequest) (*pb.ListPeersResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	devicePeers, err := wireguard.Peers()
	if err != nil {
		return nil, err
	}

	peers := []*pb.Peer{}
	for _, dp := range devicePeers {
		peer := &pb.Peer{
			PublicKey:        dp.PublicKey.String(),
			AllowedIPs:       ipsToString(dp.AllowedIPs),
			ReceivedBytes:    dp.ReceiveBytes,
			TransmittedBytes: dp.TransmitBytes,
			LastSeen:         dp.LastHandshakeTime.Unix(),
		}
		peers = append(peers, peer)
	}

	response := &pb.ListPeersResponse{
		Peers: peers,
	}
	return response, nil
}

func (w *WireguardRPCServer) ChangeListenPort(ctx context.Context, request *pb.ChangeListenPortRequest) (*pb.ChangeListenPortResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	port := int(request.GetListenPort())
	if port < 0 || port > MaxPort {
		return nil, ErrInvalidPort
	}
	err := wireguard.ChangeListenPort(port)
	if err != nil {
		return nil, err
	}

	response := &pb.ChangeListenPortResponse{
		NewListenPort: int32(wireguard.ListenPort),
	}
	return response, nil
}

func (w *WireguardRPCServer) Devices(ctx context.Context, request *pb.DevicesRequest) (*pb.DevicesResponse, error) {
	devices, err := Devices()
	if err != nil {
		return nil, err
	}

	deviceNames := []string{}
	for _, device := range devices {
		deviceNames = append(deviceNames, device.DeviceName)
	}
	response := &pb.DevicesResponse{
		Devices: deviceNames,
	}
	return response, nil
}

func ipsToString(ipNets []net.IPNet) []string {
	ips := []string{}
	for _, ip := range ipNets {
		ips = append(ips, ip.String())
	}

	return ips
}

func stringsToIPNet(cidrStrings []string) ([]net.IPNet, error) {
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
