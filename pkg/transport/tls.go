package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/samber/oops"
)

// ProtoCLIBox is the ALPN protocol identifier for cli-box transport connections.
// Clients must include this in NextProtos so the server routes them to the
// transport handler rather than the admin HTTP handler.
const ProtoCLIBox = "cli-box"

// LoadPinnedClientTLS loads the client certificate/key and pins the exact
// server certificate presented during pairing. Hostname verification is
// intentionally replaced by exact certificate matching so clients can keep
// working if the server is reached via different hostnames or IPs.
func LoadPinnedClientTLS(certFile, keyFile, serverCertFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, oops.In("transport").Wrapf(err, "load client cert")
	}

	serverCertPEM, err := os.ReadFile(serverCertFile)
	if err != nil {
		return nil, oops.In("transport").Wrapf(err, "read server cert")
	}

	pinnedCert, err := firstCertFromPEM(serverCertPEM)
	if err != nil {
		return nil, oops.In("transport").Wrapf(err, "parse pinned server cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ProtoCLIBox},
		// Exact certificate pinning now carries identity; hostname matching
		// would reject valid accesses through alternative names or IPs.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return oops.In("transport").Errorf("server did not present a certificate")
			}
			if !bytes.Equal(state.PeerCertificates[0].Raw, pinnedCert.Raw) {
				return oops.In("transport").Errorf("server certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

// LoadServerTLSDualMode builds a server TLS config that serves two protocols on
// the same port via ALPN: cli-box clients get the transport (mTLS) config;
// everything else (browsers, unknown) gets the admin HTTPS config with adminCert.
func LoadServerTLSDualMode(serverCertPEM, serverKeyPEM, caCertPEM []byte, adminCert tls.Certificate) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, oops.In("transport").Wrapf(err, "load server cert")
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, oops.In("transport").Errorf("failed to parse CA cert")
	}

	transportCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ProtoCLIBox},
	}

	adminCfg := &tls.Config{
		Certificates: []tls.Certificate{adminCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{ProtoCLIBox, "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			for _, proto := range hello.SupportedProtos {
				if proto == ProtoCLIBox {
					return transportCfg, nil
				}
			}
			return adminCfg, nil
		},
	}, nil
}

// GenerateSelfSignedCert generates an ephemeral ECDSA P-256 self-signed certificate
// for the admin HTTPS server when no --admin-cert is provided.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, oops.In("transport").Wrapf(err, "generate key")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cli-box-admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, oops.In("transport").Wrapf(err, "create certificate")
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, nil
}

func firstCertFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, oops.In("transport").Errorf("invalid certificate PEM")
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
		NextProtos:         []string{ProtoCLIBox},
	}
}
