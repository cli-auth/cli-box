package pki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	token, err := WriteNewToken(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadToken(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != token {
		t.Errorf("loaded token %q != written %q", loaded, token)
	}

	if err := ConsumeToken(stateDir); err != nil {
		t.Fatal(err)
	}

	_, err = LoadToken(stateDir)
	if err == nil {
		t.Error("expected error after consuming token")
	}
}
