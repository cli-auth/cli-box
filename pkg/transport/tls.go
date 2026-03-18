package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadPinnedClientTLS loads the client certificate/key and pins the exact
// server certificate presented during pairing. Hostname verification is
// intentionally replaced by exact certificate matching so clients can keep
// working if the server is reached via different hostnames or IPs.
func LoadPinnedClientTLS(certFile, keyFile, serverCertFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	serverCertPEM, err := os.ReadFile(serverCertFile)
	if err != nil {
		return nil, fmt.Errorf("read server cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCertPEM) {
		return nil, fmt.Errorf("failed to parse server cert")
	}
	pinnedCert, err := firstCertFromPEM(serverCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse pinned server cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		// Exact certificate pinning now carries identity; hostname matching
		// would reject valid accesses through alternative names or IPs.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("server did not present a certificate")
			}
			if !bytes.Equal(state.PeerCertificates[0].Raw, pinnedCert.Raw) {
				return fmt.Errorf("server certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

// LoadServerTLSDualMode builds a server TLS config from PEM bytes, using
// VerifyClientCertIfGiven so unauthenticated clients can still connect for pairing.
func LoadServerTLSDualMode(serverCertPEM, serverKeyPEM, caCertPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// LoadClientTLSFromPEM builds a client TLS config from PEM-encoded cert, key, and CA bytes.
func LoadClientTLSFromPEM(clientCertPEM, clientKeyPEM, caCertPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func firstCertFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// TOFUClientTLS returns a TLS config that skips server certificate verification.
// Used only during the initial pairing handshake (trust-on-first-use).
func TOFUClientTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}
}
