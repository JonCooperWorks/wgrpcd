package wireguardrpc

import (
	"context"
	"fmt"
	"net"

	"github.com/joncooperworks/wireguardrpc/pb"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		return nil, status.Errorf(codes.FailedPrecondition, "an ip address in AllowedIPs is invalid, error: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error generating private key")
	}

	peerConfig, err := wireguard.AddNewPeer(allowedIPs, key.PublicKey())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist.")
		}
		return nil, status.Errorf(codes.Internal, "error adding peer to wireguard interface: %v", err)
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
		return nil, status.Errorf(codes.Internal, "error generating private key")
	}

	allowedIPs, err := stringsToIPNet(request.GetAllowedIPs())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "an ip address in AllowedIPs is invalid, error: %v", err)
	}

	publicKey, err := wgtypes.ParseKey(request.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "invalid public key: %v", err)
	}
	peerConfig, err := wireguard.RekeyClient(allowedIPs, publicKey, key.PublicKey())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist.")
		}
		return nil, status.Errorf(codes.Internal, "error rekeying peer: %v", err)
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
		return nil, status.Errorf(codes.FailedPrecondition, "invalid public key: %v", err)
	}
	err = wireguard.RemovePeer(publicKey)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist.")
		}
		return nil, status.Errorf(codes.Internal, "error removing peer: %v", err)
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
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist.")
		}
		return nil, status.Errorf(codes.Internal, "error listing peers: %v", err)
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
		return nil, status.Errorf(codes.FailedPrecondition, "error rekeying peer: %v", ErrInvalidPort)
	}
	err := wireguard.ChangeListenPort(port)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist.")
		}
		return nil, status.Errorf(codes.Internal, "error changing listen port: %v", err)
	}

	response := &pb.ChangeListenPortResponse{
		NewListenPort: int32(wireguard.ListenPort),
	}
	return response, nil
}

func (w *WireguardRPCServer) Devices(ctx context.Context, request *pb.DevicesRequest) (*pb.DevicesResponse, error) {
	devices, err := Devices()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error listing devices: %v", err)
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
