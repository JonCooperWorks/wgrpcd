package wgrpcd

import (
	"context"
	"os"

	"github.com/joncooperworks/grpcauth"
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
	logger Logger
}

// CreatePeer adds a new Wireguard peer to the VPN.
func (s *Server) CreatePeer(ctx context.Context, request *CreatePeerRequest) (*CreatePeerResponse, error) {
	auth, err := s.authResult(ctx)
	if err != nil {
		return nil, err
	}

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

	publicKey := key.PublicKey()
	peerConfig, err := wireguard.AddNewPeer(allowedIPs, publicKey)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error adding peer to wireguard interface: %v", err)
	}

	s.logger.Printf("Client '%s' added peer '%s'", auth.ClientIdentifier, publicKey.String())
	response := &CreatePeerResponse{
		PublicKey:       peerConfig.PublicKey.String(),
		PrivateKey:      key.String(),
		AllowedIPs:      IPNetsToStrings(allowedIPs),
		ServerPublicKey: wireguard.ServerPublicKey.String(),
	}
	return response, nil
}

// RekeyPeer revokes a client's old public key and replaces it with a new one.
func (s *Server) RekeyPeer(ctx context.Context, request *RekeyPeerRequest) (*RekeyPeerResponse, error) {
	auth, err := s.authResult(ctx)
	if err != nil {
		return nil, err
	}

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

	s.logger.Printf("Client '%s' attempting to rekey peer '%s'", auth.ClientIdentifier, publicKey.String())

	peerConfig, err := wireguard.RekeyClient(allowedIPs, publicKey, key.PublicKey())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error rekeying peer: %v", err)
	}

	s.logger.Printf("Client '%s' rekeyed peer '%s'", auth.ClientIdentifier, publicKey.String())
	response := &RekeyPeerResponse{
		PublicKey:       peerConfig.PublicKey.String(),
		PrivateKey:      key.String(),
		AllowedIPs:      IPNetsToStrings(allowedIPs),
		ServerPublicKey: wireguard.ServerPublicKey.String(),
	}
	return response, nil
}

// RemovePeer deletes a peer from the Wireguard interface.
func (s *Server) RemovePeer(ctx context.Context, request *RemovePeerRequest) (*RemovePeerResponse, error) {
	auth, err := s.authResult(ctx)
	if err != nil {
		return nil, err
	}

	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	publicKey, err := wgtypes.ParseKey(request.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}

	s.logger.Printf("Client '%s' attempting to remove peer '%s'", auth.ClientIdentifier, publicKey.String())

	err = wireguard.RemovePeer(publicKey)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error removing peer: %v", err)
	}

	s.logger.Printf("Client '%s' removed peer '%s'", auth.ClientIdentifier, publicKey.String())

	response := &RemovePeerResponse{
		Removed: true,
	}
	return response, nil
}

// ListPeers returns all peers from a Wireguard device.
func (s *Server) ListPeers(ctx context.Context, request *ListPeersRequest) (*ListPeersResponse, error) {
	auth, err := s.authResult(ctx)
	if err != nil {
		return nil, err
	}

	s.logger.Printf("Client '%s' listing peers", auth.ClientIdentifier)

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

	s.logger.Printf("Client '%s' retrieved peers", auth.ClientIdentifier)

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
func (s *Server) ChangeListenPort(ctx context.Context, request *ChangeListenPortRequest) (*ChangeListenPortResponse, error) {
	auth, err := s.authResult(ctx)
	if err != nil {
		return nil, err
	}

	s.logger.Printf("Client '%s' changing listen port", auth.ClientIdentifier)

	wireguard := &Wireguard{
		DeviceName: request.GetDeviceName(),
	}

	port := int(request.GetListenPort())
	if port < 0 || port > maxPort {
		return nil, status.Errorf(codes.InvalidArgument, "port must be between 0 and %d", maxPort)
	}
	err = wireguard.ChangeListenPort(port)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
		}
		return nil, status.Errorf(codes.Internal, "error changing listen port: %v", err)
	}

	s.logger.Printf("Client '%s' changed listen port", auth.ClientIdentifier)

	response := &ChangeListenPortResponse{
		NewListenPort: int32(wireguard.ListenPort),
	}
	return response, nil
}

// Devices shows all Wireguard interfaces that can be controlled with wgrpcd.
func (s *Server) Devices(ctx context.Context, request *DevicesRequest) (*DevicesResponse, error) {
	auth, err := s.authResult(ctx)
	if err != nil {
		return nil, err
	}

	s.logger.Printf("Client '%s' looking up devices", auth.ClientIdentifier)

	devices, err := Devices()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error listing devices: %v", err)
	}

	s.logger.Printf("Client '%s' looked up devices", auth.ClientIdentifier)

	deviceNames := []string{}
	for _, device := range devices {
		deviceNames = append(deviceNames, device.DeviceName)
	}
	response := &DevicesResponse{
		Devices: deviceNames,
	}
	return response, nil
}

// Import allows loading new peers into a wgrpcd instance from a list of Peers
func (s *Server) Import(ctx context.Context, request *ImportRequest) (*ImportResponse, error) {
	auth, err := s.authResult(ctx)
	if err != nil {
		return nil, err
	}

	s.logger.Printf("Client '%s' importing peers", auth.ClientIdentifier)
	wireguard, err := New(request.GetDeviceName())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist: %s", request.GetDeviceName())
		}
		return nil, status.Errorf(codes.Internal, "error creating peer: %v", err)
	}

	for _, peer := range request.Peers {
		allowedIPs, err := StringsToIPNet(peer.AllowedIPs)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "an ip address in AllowedIPs is invalid, error: %v", err)
		}

		publicKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Invalid public key in list: %v", peer.PublicKey)
		}
		_, err = wireguard.AddNewPeer(allowedIPs, publicKey)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, status.Errorf(codes.NotFound, "that wireguard device does not exist")
			}
			return nil, status.Errorf(codes.Internal, "error adding peer to wireguard interface: %v", err)
		}
	}
	
	response := &ImportResponse{}
	return response, nil
}

func (s *Server) authResult(ctx context.Context) (*grpcauth.AuthResult, error) {
	auth, err := grpcauth.GetAuthResult(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, err.Error())
	}
	return auth, nil
}

// NewServer returns a wgrpcd instance configured to use a gRPC server with TLSv1.3.
func NewServer(config *ServerConfig) (*grpc.Server, error) {
	// Create a new TLS credentials based on the TLS configuration and return a gRPC server configured with this.
	cred := credentials.NewTLS(config.TLSConfig)

	var authFunc grpcauth.AuthFunc
	var permissionFunc grpcauth.PermissionFunc
	if config.AuthFunc != nil {
		authFunc = config.AuthFunc
	} else {
		config.Logger.Printf("WARNING: running wgrpcd using only client certificate auth")
		authFunc = NoAuth
		permissionFunc = grpcauth.NoPermissions
	}
	authority := grpcauth.NewAuthority(authFunc, permissionFunc)

	rpcServer := grpc.NewServer(
		grpc.Creds(cred),
		grpc.UnaryInterceptor(authority.UnaryServerInterceptor),
	)
	RegisterWireguardRPCServer(rpcServer, &Server{logger: config.Logger})
	return rpcServer, nil
}
