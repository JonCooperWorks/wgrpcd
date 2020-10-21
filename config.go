package wgrpcd

//ServerConfig contains all information a caller needs to create a new wgrpcd.Server.
type ServerConfig struct {
	Hostname       string
	CACertFilename string
	AuthProvider   AuthProvider
	Logger         Logger
}

// ClientConfig contains all information needed to configure a wgrpcd.Client.
type ClientConfig struct {
	GRPCAddress     string
	ClientCertBytes []byte
	ClientKeyBytes  []byte
	CACertFilename  string
}
