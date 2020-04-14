package wireguardrpc

import (
	"context"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
)

// Client interfaces with the wgrpcd gRPC API.
type Client struct {
	GrpcAddress string
	DeviceName  string
}

// connection returns a GRPC connection to ensure all gRPC connections are done in a consistent way.
// Callers of this must Close() the connection themselves.
func (c *Client) connection() (*grpc.ClientConn, error) {
	return grpc.Dial(c.GrpcAddress, grpc.WithInsecure(), grpc.WithBlock())
}

func (c *Client) CreatePeer(ctx context.Context, allowedIPs []net.IPNet) (*PeerConfigINI, error) {
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
	peerConfigINI := &PeerConfigINI{
		PrivateKey: response.PrivateKey,
		PublicKey:  response.PublicKey,
		AllowedIPs: allowedIPs,
	}
	return peerConfigINI, nil
}

func (c *Client) RekeyPeer(ctx context.Context, oldPublicKey wgtypes.Key, allowedIPs []net.IPNet) (*PeerConfigINI, error) {
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

	peerConfigINI := &PeerConfigINI{
		PrivateKey: response.PrivateKey,
		PublicKey:  response.PublicKey,
		AllowedIPs: allowedIPs,
	}
	return peerConfigINI, nil
}

func (c *Client) ChangeListenPort(ctx context.Context, listenPort int) (int32, error) {
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

	return response.NewListenPort, nil
}

func (c *Client) RemovePeer(ctx context.Context, publicKey wgtypes.Key) (bool, error) {
	conn, err := c.connection()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &RemovePeerRequest{
		PublicKey: publicKey.String(),
	}
	response, err := client.RemovePeer(ctx, request)
	if err != nil {
		return false, err
	}

	return response.Removed, nil
}

func (c *Client) ListPeers(ctx context.Context) ([]*Peer, error) {
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

	return response.Peers, nil
}

func (c *Client) Devices(ctx context.Context) ([]string, error) {
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

	return response.Devices, nil
}
