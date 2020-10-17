package wgrpcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	maxPort = 65535
)

// Server implements the operations exposed in the profobuf definitions for the gRPC server.
type Server struct {
	UnimplementedWireguardRPCServer
}

// CreatePeer adds a new Wireguard peer to the VPN.
func (w *Server) CreatePeer(ctx context.Context, request *CreatePeerRequest) (*CreatePeerResponse, error) {
	wireguard, err := New(request.GetDeviceName())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist: %s", request.GetDeviceName())
		}
		return nil, status.Errorf(codes.Internal, "error creating peer: %v", err)
	}

	allowedIPs, err := StringsToIPNet(request.GetAllowedIPs())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "an ip address in AllowedIPs is invalid, error: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error generating private key")
	}

	peerConfig, err := wireguard.AddNewPeer(allowedIPs, key.PublicKey())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error adding peer to wireguard interface: %v", err)
	}

	response := &CreatePeerResponse{
		PublicKey:       peerConfig.PublicKey.String(),
		PrivateKey:      key.String(),
		AllowedIPs:      IPNetsToStrings(allowedIPs),
		ServerPublicKey: wireguard.ServerPublicKey.String(),
	}
	return response, nil
}

// RekeyPeer revokes a client's old public key and replaces it with a new one.
func (w *Server) RekeyPeer(ctx context.Context, request *RekeyPeerRequest) (*RekeyPeerResponse, error) {
	wireguard, err := New(request.GetDeviceName())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error rekeying peer: %v", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error generating private key")
	}

	allowedIPs, err := StringsToIPNet(request.GetAllowedIPs())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "an ip address in AllowedIPs is invalid, error: %v", err)
	}

	publicKey, err := wgtypes.ParseKey(request.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}
	peerConfig, err := wireguard.RekeyClient(allowedIPs, publicKey, key.PublicKey())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error rekeying peer: %v", err)
	}

	response := &RekeyPeerResponse{
		PublicKey:       peerConfig.PublicKey.String(),
		PrivateKey:      key.String(),
		AllowedIPs:      IPNetsToStrings(allowedIPs),
		ServerPublicKey: wireguard.ServerPublicKey.String(),
	}
	return response, nil
}

// RemovePeer deletes a peer from the Wireguard interface.
func (w *Server) RemovePeer(ctx context.Context, request *RemovePeerRequest) (*RemovePeerResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	publicKey, err := wgtypes.ParseKey(request.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}
	err = wireguard.RemovePeer(publicKey)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error removing peer: %v", err)
	}

	response := &RemovePeerResponse{
		Removed: true,
	}
	return response, nil
}

// ListPeers returns all peers from a Wireguard device.
func (w *Server) ListPeers(ctx context.Context, request *ListPeersRequest) (*ListPeersResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	devicePeers, err := wireguard.Peers()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error listing peers: %v", err)
	}

	peers := []*Peer{}
	for _, dp := range devicePeers {
		peer := &Peer{
			PublicKey:        dp.PublicKey.String(),
			AllowedIPs:       IPNetsToStrings(dp.AllowedIPs),
			ReceivedBytes:    dp.ReceiveBytes,
			TransmittedBytes: dp.TransmitBytes,
			LastSeen:         dp.LastHandshakeTime.Unix(),
		}
		peers = append(peers, peer)
	}

	response := &ListPeersResponse{
		Peers: peers,
	}
	return response, nil
}

// ChangeListenPort updates the listening port wireguard is running on.
// It can be used to allow coordination with a firewall.
func (w *Server) ChangeListenPort(ctx context.Context, request *ChangeListenPortRequest) (*ChangeListenPortResponse, error) {
	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	port := int(request.GetListenPort())
	if port < 0 || port > maxPort {
		return nil, status.Errorf(codes.InvalidArgument, "port must be between 0 and %d", maxPort)
	}
	err := wireguard.ChangeListenPort(port)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error changing listen port: %v", err)
	}

	response := &ChangeListenPortResponse{
		NewListenPort: int32(wireguard.ListenPort),
	}
	return response, nil
}

// Devices shows all Wireguard interfaces that can be controlled with wgrpcd.
func (w *Server) Devices(ctx context.Context, request *DevicesRequest) (*DevicesResponse, error) {
	devices, err := Devices()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error listing devices: %v", err)
	}

	deviceNames := []string{}
	for _, device := range devices {
		deviceNames = append(deviceNames, device.DeviceName)
	}
	response := &DevicesResponse{
		Devices: deviceNames,
	}
	return response, nil
}

// NewServer returns a wgrpcd instance configured to use a gRPC server with TLSv1.3.
// wgrpcd refuses all unencrypted connections.
func NewServer(config *ServerConfig) (*grpc.Server, error) {
	serverCert, err := tls.X509KeyPair(config.ServerCertBytes, config.ServerKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	// Load the CA certificate
	trustedCert, err := ioutil.ReadFile(config.CACertFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted certificate: %w", err)
	}

	// Put the CA certificate to certificate pool
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(trustedCert) {
		return nil, fmt.Errorf("failed to append trusted certificate to certificate pool: %w", err)
	}

	// Create the TLS configuration
	// Since this is gRPC, we can enforce TLSv1.3.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      certPool,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// Create a new TLS credentials based on the TLS configuration and return a gRPC server configured with this.
	cred := credentials.NewTLS(tlsConfig)
	rpcServer := grpc.NewServer(grpc.Creds(cred))
	RegisterWireguardRPCServer(rpcServer, &Server{})
	return rpcServer, nil
}
