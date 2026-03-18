package pki

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const PairingTokenTTL = 3 * time.Minute

var now = time.Now

type PairingToken struct {
	Value     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (t PairingToken) Expired(at time.Time) bool {
	if t.ExpiresAt.IsZero() {
		return true
	}
	return !at.Before(t.ExpiresAt)
}

// InitStateDir generates a CA, server cert, and pairing token, writing them
// to the given directory. Errors if the directory already contains a CA.
func InitStateDir(dir string, hosts []string) (token string, err error) {
	caPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(caPath); err == nil {
		return "", fmt.Errorf("state dir already initialized (found %s)", caPath)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create state dir: %w", err)
	}

	caCert, caKey, err := GenerateCA()
	if err != nil {
		return "", err
	}

	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	serverCert, serverKey, err := GenerateServerCert(caCert, caKey, hosts)
	if err != nil {
		return "", err
	}

	files := map[string][]byte{
		"ca.crt":     caCert,
		"ca.key":     caKey,
		"server.crt": serverCert,
		"server.key": serverKey,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}

	token, err = WriteNewToken(dir)
	if err != nil {
		return "", err
	}
	return token, nil
}

func LoadState(dir string) (caCert, caKey, serverCert, serverKey []byte, err error) {
	caCert, err = os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read ca.crt: %w", err)
	}
	caKey, err = os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read ca.key: %w", err)
	}
	serverCert, err = os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read server.crt: %w", err)
	}
	serverKey, err = os.ReadFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read server.key: %w", err)
	}
	return caCert, caKey, serverCert, serverKey, nil
}

func LoadToken(dir string) (PairingToken, error) {
	data, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil {
		return PairingToken{}, fmt.Errorf("read token: %w", err)
	}

	var token PairingToken
	if err := json.Unmarshal(data, &token); err == nil {
		if token.Value == "" {
			return PairingToken{}, fmt.Errorf("read token: empty token")
		}
		return token, nil
	}

	legacyToken := strings.TrimSpace(string(data))
	if legacyToken == "" {
		return PairingToken{}, fmt.Errorf("read token: empty token")
	}

	// Legacy tokens had no expiry metadata. Treat them as expired so operators
	// must mint a fresh token after upgrading.
	return PairingToken{Value: legacyToken}, nil
}

// ConsumeToken deletes the token file, invalidating it for future use.
func ConsumeToken(dir string) error {
	if err := os.Remove(filepath.Join(dir, "token")); err != nil {
		return fmt.Errorf("consume token: %w", err)
	}
	return nil
}

// WriteNewToken generates a fresh token and writes it to the state dir.
func WriteNewToken(dir string) (string, error) {
	token := PairingToken{
		Value:     GenerateToken(),
		ExpiresAt: now().Add(PairingTokenTTL),
	}
	data, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("marshal token: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), data, 0o600); err != nil {
		return "", fmt.Errorf("write token: %w", err)
	}
	return token.Value, nil
}
