package main

import (
	"os"
	"syscall"
)

var notifySignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}

func isWinch(_ os.Signal) bool {
	return false
}
