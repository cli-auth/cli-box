//go:build unix

package main

import (
	"os"
	"syscall"
)

var notifySignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGWINCH}

func isWinch(sig os.Signal) bool {
	return sig == syscall.SIGWINCH
}
