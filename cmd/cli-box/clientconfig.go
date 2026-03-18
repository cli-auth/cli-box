package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cli-auth/cli-box/pkg/transport"
)

func ConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "cli-box")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cli-box")
}

// ServerConfigDir returns the config subdirectory for a given server address.
// Colons are replaced with dashes to avoid filesystem issues.
func ServerConfigDir(addr string) string {
	safe := strings.ReplaceAll(addr, ":", "-")
	return filepath.Join(ConfigDir(), safe)
}

func SavePairingResult(addr string, clientCert, clientKey, caCert []byte) error {
	dir := ServerConfigDir(addr)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	files := map[string][]byte{
		"client.crt": clientCert,
		"client.key": clientKey,
		"ca.crt":     caCert,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	// Write the server address for FindDefaultServer
	if err := os.WriteFile(filepath.Join(dir, "server"), []byte(addr), 0o600); err != nil {
		return fmt.Errorf("write server: %w", err)
	}
	return nil
}

// LoadClientConfig loads stored TLS credentials for a server. Returns nil, nil if
// no credentials are stored.
func LoadClientConfig(addr string) (*tls.Config, error) {
	dir := ServerConfigDir(addr)

	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	caFile := filepath.Join(dir, "ca.crt")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return nil, nil
	}

	return transport.LoadClientTLS(certFile, keyFile, caFile)
}

// FindDefaultServer scans the config directory and returns the server address
// if exactly one server is configured. Returns "" if zero or multiple.
func FindDefaultServer() string {
	dir := ConfigDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}

	var found string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		serverFile := filepath.Join(dir, e.Name(), "server")
		data, err := os.ReadFile(serverFile)
		if err != nil {
			continue
		}
		addr := string(data)
		if found != "" {
			return "" // multiple servers
		}
		found = addr
	}
	return found
}
