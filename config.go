package wgrpcd

import "log"

//ServerConfig contains all information a caller needs to create a new wgrpcd.Server.
type ServerConfig struct {
	ServerKeyBytes  []byte
	ServerCertBytes []byte
	CACertFilename  string
	AuthProvider    func([]string) (bool, error)
	Logger          *log.Logger
}

// ClientConfig contains all information needed to configure a wgrpcd.Client.
type ClientConfig struct {
	GRPCAddress     string
	ClientCertBytes []byte
	ClientKeyBytes  []byte
	CACertFilename  string
}
