package main

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cli-auth/cli-box/pkg/config"
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

	// FUSE root bind comes first (base layer)
	fuseRootIdx := strings.Index(full, "--bind /mnt/fuse-local /")
	if fuseRootIdx == -1 {
		t.Error("missing FUSE root bind")
	}

	// System paths overlay on top of FUSE root
	usrIdx := strings.Index(full, "--ro-bind /usr /usr")
	if usrIdx == -1 {
		t.Error("missing /usr ro-bind")
	}
	if usrIdx < fuseRootIdx {
		t.Error("system paths must come after FUSE root bind")
	}
	if !strings.Contains(full, "--ro-bind /lib /lib") {
		t.Error("missing /lib ro-bind")
	}

	// Virtual filesystems
	if !strings.Contains(full, "--proc /proc") {
		t.Error("missing --proc /proc")
	}
	if !strings.Contains(full, "--dev /dev") {
		t.Error("missing --dev /dev")
	}
	if !strings.Contains(full, "--tmpfs /tmp") {
		t.Error("missing --tmpfs /tmp")
	}

	// Credential overlay must come after FUSE root
	credIdx := strings.Index(full, "--ro-bind /secure/gh /home/idn/.config/gh")
	if credIdx == -1 {
		t.Error("missing credential bind mount")
	}
	if credIdx < fuseRootIdx {
		t.Error("credential mount must come after FUSE root bind")
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

func TestBuildBwrapArgsCwdOutsideHome(t *testing.T) {
	cfg := &SandboxConfig{
		FUSEMountpoint: "/mnt/fuse-local",
		Cwd:            "/root",
	}

	args := BuildBwrapArgs(cfg)
	full := strings.Join(args, " ")

	// FUSE root bind ensures /root exists inside sandbox
	if !strings.Contains(full, "--bind /mnt/fuse-local /") {
		t.Error("missing FUSE root bind — /root would not exist in sandbox")
	}

	// --chdir /root should be present
	if !strings.Contains(full, "--chdir /root") {
		t.Error("missing --chdir /root")
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
	specs := []config.MountSpec{
		{Source: "/secure/gh", Target: "~/.config/gh"},
	}
	mounts := ResolveCredentials(specs)
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

	// Empty specs returns nil
	if mounts := ResolveCredentials(nil); mounts != nil {
		t.Error("expected nil for empty specs")
	}
}
