package pki

import (
	"crypto/rand"
	"fmt"
)

// GenerateToken produces a random pairing token in xxxx-xxxx-xxxx hex format.
func GenerateToken() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return fmt.Sprintf("%02x%02x-%02x%02x-%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
