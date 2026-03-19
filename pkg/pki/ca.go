package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/samber/oops"
)

func GenerateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "generate CA key")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cli-box CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "create CA cert")
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "marshal CA key")
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// GenerateSelfSignedServerCert creates a self-signed server certificate for the
// supplied hostnames and IP SANs. This keeps server identity separate from the
// CA that signs client certificates.
func GenerateSelfSignedServerCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "generate server key")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cli-box server"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "create self-signed server cert")
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "marshal server key")
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// GenerateClientKey creates an ECDSA P-256 keypair and PKCS#10 CSR.
func GenerateClientKey() (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "generate client key")
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "cli-box client"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "create CSR")
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "marshal client key")
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// SignCSR signs a PEM-encoded PKCS#10 CSR with the CA, producing a client certificate.
func SignCSR(caCertPEM, caKeyPEM, csrPEM []byte) (certPEM []byte, err error) {
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, oops.In("pki").Errorf("invalid CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, oops.In("pki").Wrapf(err, "parse CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, oops.In("pki").Wrapf(err, "CSR signature check")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, oops.In("pki").Wrapf(err, "sign CSR")
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

func CertFingerprint(certDER []byte) string {
	h := sha256.Sum256(certDER)
	return "SHA256:" + hex.EncodeToString(h[:])
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, oops.In("pki").Errorf("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "parse CA cert")
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, oops.In("pki").Errorf("invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, oops.In("pki").Wrapf(err, "parse CA key")
	}
	return cert, key, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, oops.In("pki").Wrapf(err, "generate serial")
	}
	return serial, nil
}
