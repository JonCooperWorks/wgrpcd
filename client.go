package wgrpcd

import (
	"context"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
)

// Client interfaces with the wgrpcd API and marshals data between Go and the underlying transport.
type Client interface {
	CreatePeer(context.Context, []net.IPNet) (*PeerConfigInfo, error)
	RekeyPeer(context.Context, wgtypes.Key, []net.IPNet) (*PeerConfigInfo, error)
	ChangeListenPort(int) (int32, error)
	RemovePeer(context.Context, wgtypes.Key) (bool, error)
	ListPeers(context.Context) ([]*Peer, error)
	Devices(context.Context) ([]string, error)
}

// GRPCClient implements a gRPC Client for wgrpcd.
type GRPCClient struct {
	GrpcAddress string
	DeviceName  string
}

// connection returns a GRPC connection to ensure all gRPC connections are done in a consistent way.
// Callers of this must Close() the connection themselves.
func (c *GRPCClient) connection() (*grpc.ClientConn, error) {
	return grpc.Dial(c.GrpcAddress, grpc.WithInsecure(), grpc.WithBlock())
}

func (c *GRPCClient) CreatePeer(ctx context.Context, allowedIPs []net.IPNet) (*PeerConfigInfo, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &CreatePeerRequest{
		AllowedIPs: IPNetsToStrings(allowedIPs),
		DeviceName: c.DeviceName,
	}
	response, err := client.CreatePeer(ctx, request)
	if err != nil {
		return nil, err
	}
	PeerConfigInfo := &PeerConfigInfo{
		PrivateKey:      response.GetPrivateKey(),
		PublicKey:       response.GetPublicKey(),
		AllowedIPs:      allowedIPs,
		ServerPublicKey: response.GetServerPublicKey(),
	}
	return PeerConfigInfo, nil
}

func (c *GRPCClient) RekeyPeer(ctx context.Context, oldPublicKey wgtypes.Key, allowedIPs []net.IPNet) (*PeerConfigInfo, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &RekeyPeerRequest{
		PublicKey:  oldPublicKey.String(),
		AllowedIPs: IPNetsToStrings(allowedIPs),
		DeviceName: c.DeviceName,
	}
	response, err := client.RekeyPeer(ctx, request)
	if err != nil {
		return nil, err
	}

	PeerConfigInfo := &PeerConfigInfo{
		PrivateKey:      response.GetPrivateKey(),
		PublicKey:       response.GetPublicKey(),
		ServerPublicKey: response.GetServerPublicKey(),
		AllowedIPs:      allowedIPs,
	}
	return PeerConfigInfo, nil
}

func (c *GRPCClient) ChangeListenPort(ctx context.Context, listenPort int) (int32, error) {
	conn, err := c.connection()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &ChangeListenPortRequest{
		ListenPort: int32(listenPort),
		DeviceName: c.DeviceName,
	}
	response, err := client.ChangeListenPort(ctx, request)
	if err != nil {
		return 0, err
	}

	return response.GetNewListenPort(), nil
}

func (c *GRPCClient) RemovePeer(ctx context.Context, publicKey wgtypes.Key) (bool, error) {
	conn, err := c.connection()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &RemovePeerRequest{
		PublicKey:  publicKey.String(),
		DeviceName: c.DeviceName,
	}
	response, err := client.RemovePeer(ctx, request)
	if err != nil {
		return false, err
	}

	return response.GetRemoved(), nil
}

func (c *GRPCClient) ListPeers(ctx context.Context) ([]*Peer, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &ListPeersRequest{
		DeviceName: c.DeviceName,
	}
	response, err := client.ListPeers(ctx, request)
	if err != nil {
		return []*Peer{}, err
	}

	return response.GetPeers(), nil
}

func (c *GRPCClient) Devices(ctx context.Context) ([]string, error) {
	conn, err := c.connection()
	if err != nil {
		return []string{}, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &DevicesRequest{}
	response, err := client.Devices(ctx, request)
	if err != nil {
		return []string{}, err
	}

	return response.GetDevices(), nil
}
