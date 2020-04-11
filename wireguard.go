package wireguardrpc

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Wireguard represents a wireguard interface.
// It is simply a struct with the device name.
// Each call will attempt to control the device and return os.IsNotExist if the named device cannot be found.
// Wireguard is an abstraction over wgctrl to ensure callers don't leave clients open.
type Wireguard struct {
	DeviceName string
}

func Devices() ([]*Wireguard, error) {
	wireguardDevices := []*Wireguard{}
	client, err := wgctrl.New()
	if err != nil {
		return wireguardDevices, err
	}
	defer client.Close()

	devices, err := client.Devices()
	if err != nil {
		return wireguardDevices, err
	}

	for _, device := range devices {
		wireguardDevice := &Wireguard{DeviceName: device.Name}
		wireguardDevices = append(wireguardDevices, wireguardDevice)
	}

	return wireguardDevices, nil
}

// String returns the name of the interface.
func (w Wireguard) String() string {
	return w.DeviceName
}

// ChangeListenPort updates the listening port wireguard is running on.
// It can be used to allow coordination with a firewall.
func (w Wireguard) ChangeListenPort(port int) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	device, err := client.Device(w.DeviceName)
	if err != nil {
		return err
	}

	config := wgtypes.Config{
		ListenPort: &port,
	}
	return client.ConfigureDevice(device.Name, config)
}

func (w Wireguard) AddNewPeer(allowedIPs []net.IPNet, publicKey wgtypes.Key) (*wgtypes.PeerConfig, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	device, err := client.Device(w.DeviceName)
	if err != nil {
		return nil, err
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:  publicKey,
		AllowedIPs: allowedIPs,
	}
	peers := []wgtypes.PeerConfig{peerConfig}
	config := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}
	err = client.ConfigureDevice(device.Name, config)
	if err != nil {
		return nil, err
	}

	return &peerConfig, nil
}

func (w Wireguard) RekeyClient(allowedIPs []net.IPNet, oldPublicKey, newPublicKey wgtypes.Key) (*wgtypes.PeerConfig, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	device, err := client.Device(w.DeviceName)
	if err != nil {
		return nil, err
	}

	oldPeerConfig := wgtypes.PeerConfig{
		PublicKey: oldPublicKey,
		Remove:    true,
	}
	newPeerConfig := wgtypes.PeerConfig{
		PublicKey:  newPublicKey,
		AllowedIPs: allowedIPs,
	}
	peers := []wgtypes.PeerConfig{newPeerConfig, oldPeerConfig}
	config := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}
	err = client.ConfigureDevice(device.Name, config)
	if err != nil {
		return nil, err
	}

	return &newPeerConfig, nil
}

func (w Wireguard) RemovePeer(publicKey wgtypes.Key) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	device, err := client.Device(w.DeviceName)
	if err != nil {
		return err
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey: publicKey,
		Remove:    true,
	}
	peers := []wgtypes.PeerConfig{peerConfig}
	config := wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	}
	return client.ConfigureDevice(device.Name, config)
}

func (w Wireguard) Peers() ([]wgtypes.Peer, error) {
	client, err := wgctrl.New()
	if err != nil {
		return []wgtypes.Peer{}, err
	}
	defer client.Close()

	device, err := client.Device(w.DeviceName)
	if err != nil {
		return []wgtypes.Peer{}, err
	}
	return device.Peers, nil
}
