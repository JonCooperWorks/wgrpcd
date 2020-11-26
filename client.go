package wgrpcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var (
	// ConnectTimeout describes the total timeout for establishing a client
	// connection to the wgrpcd server.
	ConnectTimeout = time.Duration(10) * time.Second

	// ConnectBackoffMaxDelay configures the dialer to use the
	// provided maximum delay when backing off after
	// failed connection attempts.
	ConnectBackoffMaxDelay = time.Duration(2) * time.Second

	// KeepaliveTime is the interval at which the client sends keepalive
	// probes to the server.
	KeepaliveTime = time.Duration(30) * time.Second

	// KeepaliveTimeout is the amount of time the client waits to receive
	// a response from the server after a keepalive probe.
	KeepaliveTimeout = time.Duration(20) * time.Second
)

// PeerConfigInfo contains all information needed to configure a Wireguard peer.
type PeerConfigInfo struct {
	PrivateKey      string
	PublicKey       string
	AllowedIPs      []net.IPNet
	ServerPublicKey string
}

// Client interfaces with the wgrpcd API and marshals data between Go and the underlying transport.
type Client struct {
	GrpcAddress       string
	TLSCredentials    credentials.TransportCredentials
	AdditionalOptions []grpc.DialOption
	conn              *grpc.ClientConn
	wireguardClient   WireguardRPCClient
}

// NewClient returns a client configured with client TLS certificates and the wgrpcd instance URL.
func NewClient(config *ClientConfig) (*Client, error) {
	clientCert, err := tls.X509KeyPair(config.ClientCertBytes, config.ClientKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
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
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// Create a new TLS credentials based on the TLS configuration
	cred := credentials.NewTLS(tlsConfig)
	return &Client{
		GrpcAddress:       config.GRPCAddress,
		TLSCredentials:    cred,
		AdditionalOptions: config.Options,
	}, nil
}

// Connect makes the gRPC client dial the server and maintains a connection until the client is closed with Close.
// Callers of this must Close() the connection themselves to avoid leaks.
func (c *Client) Connect() error {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(c.TLSCredentials),
		grpc.WithTimeout(ConnectTimeout),
		grpc.WithBackoffMaxDelay(ConnectBackoffMaxDelay),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    KeepaliveTime,
			Timeout: KeepaliveTimeout,
		}),
	}
	opts = append(opts, c.AdditionalOptions...)

	conn, err := grpc.Dial(c.GrpcAddress, opts...)
	if err != nil {
		return err
	}

	c.conn = conn
	c.wireguardClient = NewWireguardRPCClient(c.conn)
	return nil
}

// checkConnection is a sanity check to ensure non-nil connections are not passed and notify a developer that they've made a mistake.
func (c *Client) checkConnection() {
	if c.conn == nil || c.wireguardClient == nil {
		panic("you must call Connect before attempting to call methods on the server")
	}
}

// Close closes a client connection and frees the resouces associated with it.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// CreatePeer calls the server's CreatePeer method and returns a Wireguard config for the newly created peer.
func (c *Client) CreatePeer(ctx context.Context, deviceName string, allowedIPs []net.IPNet) (*PeerConfigInfo, error) {
	c.checkConnection()

	request := &CreatePeerRequest{
		AllowedIPs: IPNetsToStrings(allowedIPs),
		DeviceName: deviceName,
	}
	response, err := c.wireguardClient.CreatePeer(ctx, request)
	if err != nil {
		return nil, err
	}
	peerConfigInfo := &PeerConfigInfo{
		PrivateKey:      response.GetPrivateKey(),
		PublicKey:       response.GetPublicKey(),
		AllowedIPs:      allowedIPs,
		ServerPublicKey: response.GetServerPublicKey(),
	}
	return peerConfigInfo, nil
}

// RekeyPeer wraps the server's RekeyPeer operation and returns the updated credentials.
func (c *Client) RekeyPeer(ctx context.Context, deviceName string, oldPublicKey wgtypes.Key, allowedIPs []net.IPNet) (*PeerConfigInfo, error) {
	c.checkConnection()

	request := &RekeyPeerRequest{
		PublicKey:  oldPublicKey.String(),
		AllowedIPs: IPNetsToStrings(allowedIPs),
		DeviceName: deviceName,
	}
	response, err := c.wireguardClient.RekeyPeer(ctx, request)
	if err != nil {
		return nil, err
	}

	peerConfigInfo := &PeerConfigInfo{
		PrivateKey:      response.GetPrivateKey(),
		PublicKey:       response.GetPublicKey(),
		ServerPublicKey: response.GetServerPublicKey(),
		AllowedIPs:      allowedIPs,
	}
	return peerConfigInfo, nil
}

// ChangeListenPort changes a wgrpcd's Wireguard server's listen port
func (c *Client) ChangeListenPort(ctx context.Context, deviceName string, listenPort int) (int32, error) {
	c.checkConnection()

	request := &ChangeListenPortRequest{
		ListenPort: int32(listenPort),
		DeviceName: deviceName,
	}
	response, err := c.wireguardClient.ChangeListenPort(ctx, request)
	if err != nil {
		return 0, err
	}

	return response.GetNewListenPort(), nil
}

// RemovePeer removes a peer from the Wireguard server and revokes its access.
func (c *Client) RemovePeer(ctx context.Context, deviceName string, publicKey wgtypes.Key) (bool, error) {
	c.checkConnection()

	request := &RemovePeerRequest{
		PublicKey:  publicKey.String(),
		DeviceName: deviceName,
	}
	response, err := c.wireguardClient.RemovePeer(ctx, request)
	if err != nil {
		return false, err
	}

	return response.GetRemoved(), nil
}

// ListPeers shows all peers authorized to connect to a Wireguard instance.
func (c *Client) ListPeers(ctx context.Context, deviceName string) ([]*Peer, error) {
	c.checkConnection()

	request := &ListPeersRequest{
		DeviceName: deviceName,
	}
	response, err := c.wireguardClient.ListPeers(ctx, request)
	if err != nil {
		return []*Peer{}, err
	}

	return response.GetPeers(), nil
}

// Devices returns all Wireguard interfaces controllable by wgrpcd.
func (c *Client) Devices(ctx context.Context) ([]string, error) {
	c.checkConnection()

	request := &DevicesRequest{}
	response, err := c.wireguardClient.Devices(ctx, request)
	if err != nil {
		return []string{}, err
	}

	return response.GetDevices(), nil
}
