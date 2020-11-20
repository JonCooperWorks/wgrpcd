package wgrpcd

import (
	"time"

	"google.golang.org/grpc/metadata"
)

// NoAuth always returns an AuthResult with all permissions attached.
// Use this to use wgrpcd with only mTLS client certifcate auth.
// mTLS client certifcate auth is sufficient if wgrpcd and its client(s) are on the same server.
func NoAuth(md metadata.MD) (*AuthResult, error) {
	permissions := []string{
		PermissionChangeListenPort,
		PermissionCreatePeer,
		PermissionListPeers,
		PermissionRekeyPeer,
		PermissionListDevices,
		PermissionRemovePeer,
	}
	return &AuthResult{
		ClientIdentifier: "mTLS",
		Timestamp:        time.Now(),
		Permissions:      permissions,
	}, nil
}
