package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cli-auth/cli-box/pkg/pki"
)

func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	stateDir := fs.String("state-dir", "./state", "directory for PKI state")
	host := fs.String("host", "", "hostname/IP for server cert SANs (comma-separated, default: localhost)")
	fs.Parse(args)

	var hosts []string
	if *host != "" {
		hosts = splitHosts(*host)
	}

	token, err := pki.InitStateDir(*stateDir, hosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box-server init: %v\n", err)
		return 1
	}

	fmt.Printf("Pairing token: %s\n", token)
	fmt.Println()
	fmt.Printf("Start the server:\n")
	fmt.Printf("  cli-box-server --state-dir %s\n", *stateDir)
	fmt.Println()
	fmt.Printf("Then pair a client:\n")
	fmt.Printf("  cli-box pair <host:port> --token %s\n", token)
	return 0
}

func cmdAddClient(args []string) int {
	fs := flag.NewFlagSet("add-client", flag.ExitOnError)
	stateDir := fs.String("state-dir", "./state", "directory for PKI state")
	fs.Parse(args)

	token, err := pki.WriteNewToken(*stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box-server add-client: %v\n", err)
		return 1
	}

	fmt.Printf("Pairing token: %s\n", token)
	fmt.Printf("  cli-box pair <host:port> --token %s\n", token)
	return 0
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
