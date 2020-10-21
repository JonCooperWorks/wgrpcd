package wgrpcd

import (
	"time"

	"google.golang.org/grpc/metadata"
)

// NoAuth always returns true.
// Use this to use wgrpcd with only mTLS client certifcate auth.
// mTLS client certifcate auth is sufficient if wgrpcd and its client(s) are on the same server.
func NoAuth(md metadata.MD) (*AuthResult, error) {
	return &AuthResult{
		ClientIdentifier: "mTLS",
		Timestamp:        time.Now(),
	}, nil
}
