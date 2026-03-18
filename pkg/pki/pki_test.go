package pki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA {
		t.Error("cert is not a CA")
	}
	if cert.Subject.CommonName != "cli-box CA" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("expected EC PRIVATE KEY PEM block")
	}
}

func TestGenerateServerCert(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := GenerateServerCert(caCert, caKey, []string{"example.com", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "cli-box server" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Errorf("unexpected DNS SANs: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("unexpected IP SANs: %v", cert.IPAddresses)
	}
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("missing ServerAuth EKU")
	}

	// Verify it's signed by the CA
	caBlock, _ := pem.Decode(caCert)
	ca, _ := x509.ParseCertificate(caBlock.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("cert not valid against CA: %v", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("expected EC PRIVATE KEY PEM block")
	}
}

func TestGenerateClientKeyAndSignCSR(t *testing.T) {
	caCert, caKey, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}

	keyPEM, csrPEM, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("expected EC PRIVATE KEY PEM block")
	}

	block, _ = pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("expected CERTIFICATE REQUEST PEM block")
	}

	certPEM, err := SignCSR(caCert, caKey, csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	block, _ = pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("missing ClientAuth EKU")
	}

	// Verify signed by CA
	caBlock, _ := pem.Decode(caCert)
	ca, _ := x509.ParseCertificate(caBlock.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client cert not valid against CA: %v", err)
	}
}

func TestSignCSRRejectsBadPEM(t *testing.T) {
	caCert, caKey, _ := GenerateCA()
	_, err := SignCSR(caCert, caKey, []byte("not a PEM"))
	if err == nil {
		t.Error("expected error for bad PEM")
	}
}

func TestCertFingerprint(t *testing.T) {
	certPEM, _, _ := GenerateCA()
	block, _ := pem.Decode(certPEM)
	fp := CertFingerprint(block.Bytes)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("unexpected fingerprint format: %s", fp)
	}
	if len(fp) != 7+64 { // "SHA256:" + 32 bytes hex
		t.Errorf("unexpected fingerprint length: %d", len(fp))
	}
}

func TestGenerateToken(t *testing.T) {
	token := GenerateToken()
	// Format: xxxx-xxxx-xxxx (4-4-4 hex chars)
	parts := strings.Split(token, "-")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), token)
	}
	for i, p := range parts {
		if len(p) != 4 {
			t.Errorf("part %d length = %d, want 4: %s", i, len(p), p)
		}
	}

	// Uniqueness
	token2 := GenerateToken()
	if token == token2 {
		t.Error("two tokens should not be equal")
	}
}

func TestInitAndLoadStateDir(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")

	token, err := InitStateDir(stateDir, []string{"myhost.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Error("empty token")
	}

	caCert, caKey, serverCert, serverKey, err := LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{caCert, caKey, serverCert, serverKey} {
		if len(b) == 0 {
			t.Error("empty PEM data")
		}
	}

	// Verify server cert has the right SAN
	block, _ := pem.Decode(serverCert)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "myhost.example.com" {
		t.Errorf("unexpected server SANs: %v", cert.DNSNames)
	}

	// Init again should fail
	_, err = InitStateDir(stateDir, nil)
	if err == nil {
		t.Error("expected error on re-init")
	}
}

func TestTokenOperations(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	os.MkdirAll(stateDir, 0o700)

	fixedNow := time.Date(2026, time.March, 18, 10, 0, 0, 0, time.UTC)
	prevNow := now
	now = func() time.Time { return fixedNow }
	defer func() { now = prevNow }()

	token, err := WriteNewToken(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadToken(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Value != token {
		t.Errorf("loaded token %q != written %q", loaded.Value, token)
	}
	if got, want := loaded.ExpiresAt, fixedNow.Add(PairingTokenTTL); !got.Equal(want) {
		t.Errorf("expires at %s, want %s", got, want)
	}

	if err := ConsumeToken(stateDir); err != nil {
		t.Fatal(err)
	}

	_, err = LoadToken(stateDir)
	if err == nil {
		t.Error("expected error after consuming token")
	}
}

func TestLoadTokenTreatsLegacyFormatAsExpired(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "token"), []byte("abcd-1234-ef56\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	token, err := LoadToken(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if token.Value != "abcd-1234-ef56" {
		t.Fatalf("unexpected legacy token value %q", token.Value)
	}
	if !token.Expired(time.Now()) {
		t.Fatal("legacy token should be treated as expired")
	}
}

func TestWriteNewTokenPersistsJSONMetadata(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	fixedNow := time.Date(2026, time.March, 18, 11, 0, 0, 0, time.UTC)
	prevNow := now
	now = func() time.Time { return fixedNow }
	defer func() { now = prevNow }()

	token, err := WriteNewToken(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(stateDir, "token"))
	if err != nil {
		t.Fatal(err)
	}

	var stored PairingToken
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("token file should be JSON: %v", err)
	}
	if stored.Value != token {
		t.Fatalf("stored token %q != written token %q", stored.Value, token)
	}
	if got, want := stored.ExpiresAt, fixedNow.Add(PairingTokenTTL); !got.Equal(want) {
		t.Fatalf("expires at %s, want %s", got, want)
	}
}
