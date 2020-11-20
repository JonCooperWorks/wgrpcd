package wgrpcd

// Permissions allow wgrpcd to limit access to methods on its gRPC server based on configuration with an OpenID provider.
// The permissions in this file are meant to allow admins to limit access to wgrpcd functions.
// These permissions should be passed as scopes in the JWT from the OpenID provider.
const (
	// PermissionChangeListenPort allows a client to change the Wireguard VPN's listening port
	PermissionChangeListenPort = "/wgrpcd.WireguardRPC/ChangeListenPort"

	// PermissionCreatePeer allows a client to create a new peer on the Wiregurd interface.
	PermissionCreatePeer = "/wgrpcd.WireguardRPC/CreatePeer"

	// PermissionRekeyPeer allows a client to rekey a peer.
	PermissionRekeyPeer = "/wgrpcd.WireguardRPC/RekeyPeer"

	// PermissionRemovePeer allows a client to remove a peer from the interface.
	PermissionRemovePeer = "/wgrpcd.WireguardRPC/RemovePeer"

	// PermissionListPeers allows a client to list active peers.
	PermissionListPeers = "/wgrpcd.WireguardRPC/ListPeers"

	// PermissionListDevices allows a client to list active Wireguard interfaces on a host.
	PermissionListDevices = "/wgrpcd.WireguardRPC/Devices"
)
