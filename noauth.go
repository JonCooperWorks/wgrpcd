package wgrpcd

import (
	"time"

	"github.com/joncooperworks/grpcauth"
	"google.golang.org/grpc/metadata"
)

// NoAuth always returns an grpcauth.AuthResult with all permissions attached.
// Use this to use wgrpcd with only mTLS client certifcate auth.
// mTLS client certifcate auth is sufficient if wgrpcd and its client(s) are on the same server.
func NoAuth(md metadata.MD) (*grpcauth.AuthResult, error) {
	return &grpcauth.AuthResult{
		ClientIdentifier: "mTLS",
		Timestamp:        time.Now(),
	}, nil
}
