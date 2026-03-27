package main

import (
	"crypto/tls"
	"fmt"

	"github.com/samber/oops"
)

type PingCmd struct{}

// Run dials the configured server using stored mTLS credentials to test that
// the current pairing is valid and the server is reachable.
func (cmd *PingCmd) Run() error {
	cfg, err := loadStubConfig()
	if err != nil {
		return err
	}
	conn, err := tls.Dial("tcp", cfg.ServerAddr, cfg.TLS)
	if err != nil {
		return oops.In("client").With("addr", cfg.ServerAddr).Wrapf(err, "connect")
	}
	conn.Close()
	fmt.Printf("connected: %s\n", cfg.ServerAddr)
	return nil
}
