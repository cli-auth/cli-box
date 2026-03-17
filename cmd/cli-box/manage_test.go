package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSymlinkSetupAndRemove(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	os.MkdirAll(binDir, 0o755)

	// Create a fake binary to be the symlink target
	fakeBin := filepath.Join(tmpDir, "cli-box")
	os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755)

	t.Setenv("CLI_BOX_BIN_DIR", binDir)

	// Manually create symlinks like setup would
	link := filepath.Join(binDir, "gh")
	if err := os.Symlink(fakeBin, link); err != nil {
		t.Fatal(err)
	}

	// Verify it exists
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if target != fakeBin {
		t.Fatalf("expected %s, got %s", fakeBin, target)
	}

	// Remove the symlink
	os.Remove(link)
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("symlink should be removed")
	}
}

func TestStubBinDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CLI_BOX_BIN_DIR", tmpDir)

	if got := stubBinDir(); got != tmpDir {
		t.Fatalf("expected %s, got %s", tmpDir, got)
	}
}

func TestStubBinDirDefault(t *testing.T) {
	t.Setenv("CLI_BOX_BIN_DIR", "")
	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, ".local", "bin")
	if got := stubBinDir(); got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}
