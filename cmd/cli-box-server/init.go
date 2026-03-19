package main

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/oops"

	"github.com/cli-auth/cli-box/pkg/pki"
)

type InitCmd struct {
	StateDir string `help:"Directory for PKI state." default:"./state"`
	Host     string `help:"Hostname or IP SANs for the server certificate." placeholder:"HOST[,HOST...]"`
}

type AddClientCmd struct {
	StateDir string `help:"Directory for PKI state." default:"./state"`
}

type DumpConfigCmd struct{}

func (cmd *InitCmd) Run() error {
	var hosts []string
	if cmd.Host != "" {
		hosts = splitHosts(cmd.Host)
	}

	token, err := pki.InitStateDir(cmd.StateDir, hosts)
	if err != nil {
		return oops.In("pki").Wrapf(err, "init PKI state")
	}

	fp, err := loadServerFingerprint(cmd.StateDir)
	if err != nil {
		return err
	}

	fmt.Printf("Pairing token: %s\n", token)
	fmt.Printf("Token expires in %d minutes\n", int(pki.PairingTokenTTL/time.Minute))
	fmt.Printf("Server fingerprint: %s\n", fp)
	fmt.Println()
	fmt.Printf("Start the server:\n")
	fmt.Printf("  cli-box-server serve --state-dir %s\n", cmd.StateDir)
	fmt.Println()
	fmt.Printf("Then pair a client:\n")
	fmt.Printf("  cli-box pair <host:port> --token %s\n", token)
	return nil
}

func (cmd *AddClientCmd) Run() error {
	token, err := pki.WriteNewToken(cmd.StateDir)
	if err != nil {
		return oops.In("pki").Wrapf(err, "write pairing token")
	}

	fp, err := loadServerFingerprint(cmd.StateDir)
	if err != nil {
		return err
	}

	fmt.Printf("Pairing token: %s\n", token)
	fmt.Printf("Server fingerprint: %s\n", fp)
	fmt.Printf("Token expires in %d minutes\n", int(pki.PairingTokenTTL/time.Minute))
	fmt.Printf("  cli-box pair <host:port> --token %s\n", token)
	return nil
}

func loadServerFingerprint(stateDir string) (string, error) {
	serverCertPEM, err := os.ReadFile(filepath.Join(stateDir, "server.crt"))
	if err != nil {
		return "", oops.In("pki").With("file", "server.crt").Wrapf(err, "read state")
	}

	block, _ := pem.Decode(serverCertPEM)
	if block == nil {
		return "", oops.In("pki").Errorf("parse server cert PEM: invalid PEM")
	}

	return pki.CertFingerprint(block.Bytes), nil
}

func splitHosts(s string) []string {
	var hosts []string
	for _, h := range splitComma(s) {
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func splitComma(s string) []string {
	var result []string
	start := 0
	for i := range len(s) {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}
