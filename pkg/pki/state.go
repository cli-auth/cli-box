package pki

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samber/oops"
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

// InitStateDir generates the client-signing CA, the server TLS certificate, and
// a pairing token, writing them to the given directory.
func InitStateDir(dir string, hosts []string) (token string, err error) {
	clientCAPath := filepath.Join(dir, "client_ca.crt")
	if _, err := os.Stat(clientCAPath); err == nil {
		return "", oops.In("pki").Errorf("state dir already initialized (found %s)", clientCAPath)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", oops.In("pki").Wrapf(err, "create state dir")
	}

	clientCACert, clientCAKey, err := GenerateCA()
	if err != nil {
		return "", err
	}

	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	serverCert, serverKey, err := GenerateSelfSignedServerCert(hosts)
	if err != nil {
		return "", err
	}

	files := map[string][]byte{
		"client_ca.crt": clientCACert,
		"client_ca.key": clientCAKey,
		"server.crt":    serverCert,
		"server.key":    serverKey,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return "", oops.In("pki").With("file", name).Wrapf(err, "write state file")
		}
	}

	token, err = WriteNewToken(dir)
	if err != nil {
		return "", err
	}
	return token, nil
}

func LoadState(dir string) (clientCACert, clientCAKey, serverCert, serverKey []byte, err error) {
	clientCACert, err = os.ReadFile(filepath.Join(dir, "client_ca.crt"))
	if err != nil {
		return nil, nil, nil, nil, oops.In("pki").With("file", "client_ca.crt").Wrapf(err, "read state")
	}
	clientCAKey, err = os.ReadFile(filepath.Join(dir, "client_ca.key"))
	if err != nil {
		return nil, nil, nil, nil, oops.In("pki").With("file", "client_ca.key").Wrapf(err, "read state")
	}
	serverCert, err = os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		return nil, nil, nil, nil, oops.In("pki").With("file", "server.crt").Wrapf(err, "read state")
	}
	serverKey, err = os.ReadFile(filepath.Join(dir, "server.key"))
	if err != nil {
		return nil, nil, nil, nil, oops.In("pki").With("file", "server.key").Wrapf(err, "read state")
	}
	return clientCACert, clientCAKey, serverCert, serverKey, nil
}

func LoadToken(dir string) (PairingToken, error) {
	data, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil {
		return PairingToken{}, oops.In("pki").Wrapf(err, "read token")
	}

	var token PairingToken
	if err := json.Unmarshal(data, &token); err == nil {
		if token.Value == "" {
			return PairingToken{}, oops.In("pki").Errorf("read token: empty token")
		}
		return token, nil
	}

	legacyToken := strings.TrimSpace(string(data))
	if legacyToken == "" {
		return PairingToken{}, oops.In("pki").Errorf("read token: empty token")
	}

	// Legacy tokens had no expiry metadata. Treat them as expired so operators
	// must mint a fresh token after upgrading.
	return PairingToken{Value: legacyToken}, nil
}

// ConsumeToken deletes the token file, invalidating it for future use.
func ConsumeToken(dir string) error {
	if err := os.Remove(filepath.Join(dir, "token")); err != nil {
		return oops.In("pki").Wrapf(err, "consume token")
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
		return "", oops.In("pki").Wrapf(err, "marshal token")
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), data, 0o600); err != nil {
		return "", oops.In("pki").Wrapf(err, "write token")
	}
	return token.Value, nil
}
