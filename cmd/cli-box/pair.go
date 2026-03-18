package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/hashicorp/yamux"
	"golang.org/x/term"

	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

type PairCmd struct {
	Addr  string `arg:"" name:"host:port" help:"Remote cli-box-server address."`
	Token string `help:"One-time pairing token." required:""`
}

func (cmd *PairCmd) Run() error {
	keyPEM, csrPEM, err := pki.GenerateClientKey()
	if err != nil {
		return fmt.Errorf("cli-box pair: generate key: %w", err)
	}

	tlsCfg := transport.TOFUClientTLS()
	conn, err := tls.Dial("tcp", cmd.Addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("cli-box pair: connect to %s: %w", cmd.Addr, err)
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
				return fmt.Errorf("cli-box pair: aborted")
			}
		}
	}

	session, err := yamux.Client(conn, nil)
	if err != nil {
		return fmt.Errorf("cli-box pair: yamux: %w", err)
	}
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		return fmt.Errorf("cli-box pair: peer: %w", err)
	}
	go peer.Serve()
	defer peer.Close()

	pairingClient := pb.NewPairingClient(peer.ClientConn)
	resp, err := pairingClient.Pair(context.Background(), &pb.PairRequest{
		Token: cmd.Token,
		Csr:   csrPEM,
	})
	if err != nil {
		return fmt.Errorf("cli-box pair: %w", err)
	}

	// Verify the returned client cert is signed by the returned CA
	if err := verifyPairedCert(resp.ClientCert, resp.CaCert); err != nil {
		return fmt.Errorf("cli-box pair: certificate verification failed: %w", err)
	}

	if err := SavePairingResult(cmd.Addr, resp.ClientCert, keyPEM, resp.CaCert); err != nil {
		return fmt.Errorf("cli-box pair: save credentials: %w", err)
	}

	fmt.Printf("Paired. Credentials stored in %s\n", ConfigDir())
	return nil
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
