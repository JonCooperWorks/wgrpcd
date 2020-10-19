package wgrpcd

// NoAuthProvider always returns true.
// Use this to use wgrpcd with only mTLS client certifcate auth.
// mTLS Client certifcate auth is sufficient if wgrpcd is running on the same server as its client.
func NoAuthProvider(authorization []string) (bool, error) {
	return true, nil
}
