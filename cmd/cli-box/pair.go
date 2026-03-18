package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/hashicorp/yamux"
	"golang.org/x/term"

	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

func cmdPair(args []string) int {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	token := fs.String("token", "", "one-time pairing token (required)")
	fs.Parse(args)

	if fs.NArg() < 1 || *token == "" {
		fmt.Fprintln(os.Stderr, "usage: cli-box pair <host:port> --token <token>")
		return 1
	}
	addr := fs.Arg(0)

	keyPEM, csrPEM, err := pki.GenerateClientKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box pair: generate key: %v\n", err)
		return 1
	}

	tlsCfg := transport.TOFUClientTLS()
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box pair: connect to %s: %v\n", addr, err)
		return 1
	}
	defer conn.Close()

	// Show server certificate fingerprint for TOFU verification
	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		fp := pki.CertFingerprint(state.PeerCertificates[0].Raw)
		fmt.Printf("Server fingerprint: %s\n", fp)
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Print("Trust this server? [y/N] ")
			var answer string
			fmt.Scanln(&answer)
			if answer != "y" && answer != "Y" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				return 1
			}
		}
	}

	session, err := yamux.Client(conn, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box pair: yamux: %v\n", err)
		return 1
	}
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box pair: peer: %v\n", err)
		return 1
	}
	go peer.Serve()
	defer peer.Close()

	pairingClient := pb.NewPairingClient(peer.ClientConn)
	resp, err := pairingClient.Pair(context.Background(), &pb.PairRequest{
		Token: *token,
		Csr:   csrPEM,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box pair: %v\n", err)
		return 1
	}

	// Verify the returned client cert is signed by the returned CA
	if err := verifyPairedCert(resp.ClientCert, resp.CaCert); err != nil {
		fmt.Fprintf(os.Stderr, "cli-box pair: certificate verification failed: %v\n", err)
		return 1
	}

	if err := SavePairingResult(addr, resp.ClientCert, keyPEM, resp.CaCert); err != nil {
		fmt.Fprintf(os.Stderr, "cli-box pair: save credentials: %v\n", err)
		return 1
	}

	fmt.Printf("Paired. Credentials stored in %s\n", ServerConfigDir(addr))
	return 0
}

func verifyPairedCert(clientCertPEM, caCertPEM []byte) error {
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("invalid CA cert PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	block, _ = pem.Decode(clientCertPEM)
	if block == nil {
		return fmt.Errorf("invalid client cert PEM")
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse client cert: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}
