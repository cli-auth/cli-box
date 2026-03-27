package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/hashicorp/yamux"
	"github.com/samber/oops"
	"golang.org/x/term"

	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

type PairCmd struct {
	Addr        string `arg:"" name:"host:port" help:"Remote cli-box-server address."`
	Token       string `help:"One-time pairing token." required:""`
	Fingerprint string `help:"Expected server fingerprint for headless verification (sha256:...)."`
}

func (cmd *PairCmd) Run() error {
	keyPEM, csrPEM, err := pki.GenerateClientKey()
	if err != nil {
		return oops.In("client").Wrapf(err, "generate key")
	}

	tlsCfg := transport.TOFUClientTLS()
	conn, err := tls.Dial("tcp", cmd.Addr, tlsCfg)
	if err != nil {
		return oops.In("client").With("addr", cmd.Addr).Wrapf(err, "connect")
	}
	defer conn.Close()

	// Show server certificate fingerprint for TOFU verification
	state := conn.ConnectionState()
	var serverCertPEM []byte
	if len(state.PeerCertificates) > 0 {
		fp := pki.CertFingerprint(state.PeerCertificates[0].Raw)
		serverCertPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: state.PeerCertificates[0].Raw,
		})
		fmt.Printf("Server fingerprint: %s\n", fp)
		if cmd.Fingerprint != "" {
			// Headless: verify fingerprint matches before proceeding.
			if fp != cmd.Fingerprint {
				return oops.In("client").Errorf("fingerprint mismatch: expected %s, got %s", cmd.Fingerprint, fp)
			}
		} else if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Print("Trust this server? [y/N] ")
			var answer string
			fmt.Scanln(&answer)
			if answer != "y" && answer != "Y" {
				return oops.In("client").Errorf("pairing aborted")
			}
		} else {
			return oops.In("client").Errorf("non-interactive pairing requires --fingerprint")
		}
	}
	if len(serverCertPEM) == 0 {
		return oops.In("client").Errorf("server did not present a certificate")
	}

	session, err := yamux.Client(conn, nil)
	if err != nil {
		return oops.In("client").Wrapf(err, "yamux")
	}
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		return oops.In("client").Wrapf(err, "peer setup")
	}
	go peer.Serve()
	defer peer.Close()

	pairingClient := pb.NewPairingClient(peer.ClientConn)
	resp, err := pairingClient.Pair(context.Background(), &pb.PairRequest{
		Token: cmd.Token,
		Csr:   csrPEM,
	})
	if err != nil {
		return oops.In("client").Wrapf(err, "pairing RPC")
	}

	// Verify the returned client cert is signed by the returned CA
	if err := verifyPairedCert(resp.ClientCert, resp.CaCert); err != nil {
		return oops.In("client").Wrapf(err, "certificate verification")
	}

	if err := SavePairingResult(cmd.Addr, resp.ClientCert, keyPEM, resp.CaCert, serverCertPEM); err != nil {
		return oops.In("client").Wrapf(err, "save credentials")
	}

	fmt.Printf("Paired. Credentials stored in %s\n", ConfigDir())
	return nil
}

func verifyPairedCert(clientCertPEM, caCertPEM []byte) error {
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return oops.In("client").Errorf("invalid CA cert PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return oops.In("client").Wrapf(err, "parse CA cert")
	}

	block, _ = pem.Decode(clientCertPEM)
	if block == nil {
		return oops.In("client").Errorf("invalid client cert PEM")
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return oops.In("client").Wrapf(err, "parse client cert")
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}
