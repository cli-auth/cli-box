package main

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildBwrapArgs(t *testing.T) {
	cfg := &SandboxConfig{
		FUSEMountpoint: "/mnt/fuse-local",
		Credentials: []BindMount{
			{Source: "/secure/gh", Target: "/home/idn/.config/gh", ReadOnly: true},
		},
		Cwd: "/home/idn/project",
	}

	args := BuildBwrapArgs(cfg)
	full := strings.Join(args, " ")

	// System paths come first
	if !strings.Contains(full, "--ro-bind /usr /usr") {
		t.Error("missing /usr ro-bind")
	}
	if !strings.Contains(full, "--ro-bind /lib /lib") {
		t.Error("missing /lib ro-bind")
	}

	// FUSE-backed paths
	if !strings.Contains(full, "--bind /mnt/fuse-local/etc /etc") {
		t.Error("missing FUSE /etc bind")
	}
	if !strings.Contains(full, "--bind /mnt/fuse-local/home /home") {
		t.Error("missing FUSE /home bind")
	}

	// Credential overlay must come after FUSE binds
	fuseHomeIdx := strings.Index(full, "--bind /mnt/fuse-local/home /home")
	credIdx := strings.Index(full, "--ro-bind /secure/gh /home/idn/.config/gh")
	if credIdx == -1 {
		t.Error("missing credential bind mount")
	}
	if credIdx < fuseHomeIdx {
		t.Error("credential mount must come after FUSE home mount")
	}

	// Working directory
	if !strings.Contains(full, "--chdir /home/idn/project") {
		t.Error("missing --chdir")
	}

	// Terminator
	if args[len(args)-1] != "--" {
		t.Error("args should end with --")
	}
}

func TestWrapCommand(t *testing.T) {
	cfg := &SandboxConfig{
		FUSEMountpoint: "/mnt/fuse-local",
		Cwd:            "/home/idn",
	}

	wrapped := cfg.WrapCommand([]string{"gh", "pr", "list"})
	if wrapped[0] != "bwrap" {
		t.Error("first arg should be bwrap")
	}
	// Last 3 args should be the original command
	tail := wrapped[len(wrapped)-3:]
	if tail[0] != "gh" || tail[1] != "pr" || tail[2] != "list" {
		t.Errorf("expected [gh pr list], got %v", tail)
	}
}

func TestResolveCredentials(t *testing.T) {
	mounts := ResolveCredentials("gh")
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if mounts[0].Source != "/secure/gh" {
		t.Errorf("expected source /secure/gh, got %s", mounts[0].Source)
	}

	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}
	expectedTarget := filepath.Join(u.HomeDir, ".config/gh")
	if mounts[0].Target != expectedTarget {
		t.Errorf("expected target %s, got %s", expectedTarget, mounts[0].Target)
	}
	if !mounts[0].ReadOnly {
		t.Error("credential mounts should be read-only")
	}

	// Unknown CLI returns nil
	if mounts := ResolveCredentials("unknown-cli"); mounts != nil {
		t.Error("expected nil for unknown CLI")
	}
}
