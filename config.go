package wgrpcd

//ServerConfig contains all information a caller needs to create a new wgrpcd.Server.
type ServerConfig struct {
	ServerKeyFilename  string
	ServerCertFilename string
	CACertFilename     string
}

// ClientConfig contains all information needed to configure a wgrpcd.Client.
type ClientConfig struct {
	GrpcAddress        string
	DeviceName         string
	ClientCertFilename string
	ClientKeyFilename  string
	CACertFilename     string
}
