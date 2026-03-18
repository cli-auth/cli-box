package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSavePairingResultStoresSingleServerConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	addr := "10.10.10.10:9443"
	if err := SavePairingResult(addr, []byte("crt"), []byte("key"), []byte("client-ca"), []byte("server-crt")); err != nil {
		t.Fatal(err)
	}

	dir := ConfigDir()
	for _, name := range []string{"client.crt", "client.key", "client_ca.crt", "server.crt", "server"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to be written: %v", name, err)
		}
	}

	if got := LoadConfiguredServer(); got != addr {
		t.Fatalf("configured server = %q, want %q", got, addr)
	}
}
