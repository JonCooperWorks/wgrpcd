package wgrpcd

import (
	"crypto/tls"

	"github.com/joncooperworks/grpcauth"
	"google.golang.org/grpc"
)

//ServerConfig contains all information a caller needs to create a new wgrpcd.Server.
type ServerConfig struct {
	TLSConfig      *tls.Config
	CACertFilename string
	AuthFunc       grpcauth.AuthFunc
	PermissionFunc grpcauth.PermissionFunc
	Logger         Logger
}

// ClientConfig contains all information needed to configure a wgrpcd.Client.
// Client authentication can be configured using the Options []DialOption.
type ClientConfig struct {
	GRPCAddress     string
	ClientCertBytes []byte
	ClientKeyBytes  []byte
	CACertFilename  string
	Options         []grpc.DialOption
}
