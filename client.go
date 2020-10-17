package wgrpcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client interfaces with the wgrpcd API and marshals data between Go and the underlying transport.
// It allows controlling a single device at a time.
type Client struct {
	GrpcAddress    string
	DeviceName     string
	TLSCredentials credentials.TransportCredentials
}

// NewClient returns a client configured with
func NewClient(config *ClientConfig) (*Client, error) {
	clientCert, err := tls.X509KeyPair(config.ClientCertBytes, config.ClientKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key. %w", err)
	}

	// Load the CA certificate
	trustedCert, err := ioutil.ReadFile(config.CACertFilename)
	if err != nil {
		return nil, fmt.Errorf("Failed to load trusted certificate. %w", err)
	}

	// Put the CA certificate to certificate pool
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(trustedCert) {
		return nil, fmt.Errorf("failed to append trusted certificate to certificate pool. %w", err)
	}

	// Create the TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// Create a new TLS credentials based on the TLS configuration
	cred := credentials.NewTLS(tlsConfig)
	return &Client{
		GrpcAddress:    config.GRPCAddress,
		TLSCredentials: cred,
	}, nil
}

// connection returns a GRPC connection to ensure all gRPC connections are done in a consistent way.
// Callers of this must Close() the connection themselves.
func (c *Client) connection() (*grpc.ClientConn, error) {
	return grpc.Dial(c.GrpcAddress, grpc.WithTransportCredentials(c.TLSCredentials))
}

// CreatePeer calls the server's CreatePeer method and returns a Wireguard config for the newly created peer.
func (c *Client) CreatePeer(ctx context.Context, deviceName string, allowedIPs []net.IPNet) (*PeerConfigInfo, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &CreatePeerRequest{
		AllowedIPs: IPNetsToStrings(allowedIPs),
		DeviceName: deviceName,
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

// RekeyPeer wraps the server's RekeyPeer operation and returns the updated credentials.
func (c *Client) RekeyPeer(ctx context.Context, deviceName string, oldPublicKey wgtypes.Key, allowedIPs []net.IPNet) (*PeerConfigInfo, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &RekeyPeerRequest{
		PublicKey:  oldPublicKey.String(),
		AllowedIPs: IPNetsToStrings(allowedIPs),
		DeviceName: deviceName,
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

// ChangeListenPort changes a wgrpcd's Wireguard server's listen port
func (c *Client) ChangeListenPort(ctx context.Context, deviceName string, listenPort int) (int32, error) {
	conn, err := c.connection()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &ChangeListenPortRequest{
		ListenPort: int32(listenPort),
		DeviceName: deviceName,
	}
	response, err := client.ChangeListenPort(ctx, request)
	if err != nil {
		return 0, err
	}

	return response.GetNewListenPort(), nil
}

// RemovePeer removes a peer from the Wireguard server and revokes its access.
func (c *Client) RemovePeer(ctx context.Context, deviceName string, publicKey wgtypes.Key) (bool, error) {
	conn, err := c.connection()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &RemovePeerRequest{
		PublicKey:  publicKey.String(),
		DeviceName: deviceName,
	}
	response, err := client.RemovePeer(ctx, request)
	if err != nil {
		return false, err
	}

	return response.GetRemoved(), nil
}

// ListPeers shows all peers authorized to connect to a Wireguard instance.
func (c *Client) ListPeers(ctx context.Context, deviceName string) ([]*Peer, error) {
	conn, err := c.connection()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := NewWireguardRPCClient(conn)
	request := &ListPeersRequest{
		DeviceName: deviceName,
	}
	response, err := client.ListPeers(ctx, request)
	if err != nil {
		return []*Peer{}, err
	}

	return response.GetPeers(), nil
}

// Devices returns all Wireguard interfaces controllable by wgrpcd.
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

	return response.GetDevices(), nil
}
