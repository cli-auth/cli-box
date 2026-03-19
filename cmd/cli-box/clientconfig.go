package main

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"

	"github.com/samber/oops"

	"github.com/cli-auth/cli-box/pkg/transport"
)

func ConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "cli-box")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cli-box")
}

func SavePairingResult(addr string, clientCert, clientKey, clientCACert, serverCert []byte) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return oops.In("client").Wrapf(err, "create config dir")
	}

	files := map[string][]byte{
		"client.crt":    clientCert,
		"client.key":    clientKey,
		"client_ca.crt": clientCACert,
		"server.crt":    serverCert,
		"server":        []byte(addr),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return oops.In("client").With("file", name).Wrapf(err, "write config file")
		}
	}

	return nil
}

// LoadClientConfig loads stored TLS credentials for the configured server.
// Returns nil, nil if no credentials are stored.
func LoadClientConfig() (*tls.Config, error) {
	dir := ConfigDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	serverCertFile := filepath.Join(dir, "server.crt")

	tlsCfg, err := transport.LoadPinnedClientTLS(certFile, keyFile, serverCertFile)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return tlsCfg, err
}

// LoadConfiguredServer returns the configured remote server address.
func LoadConfiguredServer() string {
	data, err := os.ReadFile(filepath.Join(ConfigDir(), "server"))
	if err != nil {
		return ""
	}
	return string(data)
}
