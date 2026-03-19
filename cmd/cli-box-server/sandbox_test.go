package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cli-auth/cli-box/pkg/config"
)

func TestBuildBwrapArgs(t *testing.T) {
	fuseRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(fuseRoot, "Users", "foo", "project"))
	mustMkdirAll(t, filepath.Join(fuseRoot, "Users", "foo", ".config"))
	mustMkdirAll(t, filepath.Join(fuseRoot, "private", "etc"))
	mustMkdirAll(t, filepath.Join(fuseRoot, "var", "tmp"))
	mustMkdirAll(t, filepath.Join(fuseRoot, "sys", "kernel"))
	mustSymlink(t, "private/etc", filepath.Join(fuseRoot, "etc"))
	mustSymlink(t, "private/tmp", filepath.Join(fuseRoot, "tmp"))
	mustMkdirAll(t, filepath.Join(fuseRoot, "usr", "local"))
	mustWriteFile(t, filepath.Join(fuseRoot, "README"), []byte("skip regular files"))

	cfg := &SandboxConfig{
		FUSEMountpoint: fuseRoot,
		Credentials: []BindMount{
			{Source: "/secure/gh", Target: "/Users/foo/.config/gh", ReadOnly: false},
		},
		Cwd:         "/Users/foo/project",
		MountPolicy: MountPolicyIdentity,
	}

	args := BuildBwrapArgs(cfg)
	full := strings.Join(args, " ")

	if !hasSequence(args, "--tmpfs", "/") {
		t.Fatal("missing synthetic root tmpfs")
	}

	runtimeIdx := -1
	for _, path := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}

		var seq []string
		switch {
		case info.IsDir():
			seq = []string{"--ro-bind", path, path}
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				t.Fatalf("readlink %s: %v", path, err)
			}
			seq = []string{"--symlink", target, path}
		default:
			continue
		}

		idx := sequenceIndex(args, seq...)
		if idx == -1 {
			t.Fatalf("missing runtime mount for %s", path)
		}
		if runtimeIdx == -1 {
			runtimeIdx = idx
		}
	}

	if runtimeIdx == -1 {
		t.Fatal("expected at least one runtime mount")
	}

	if !hasSequence(args, "--proc", "/proc") {
		t.Error("missing --proc /proc")
	}
	if !hasSequence(args, "--dev", "/dev") {
		t.Error("missing --dev /dev")
	}
	if !hasSequence(args, "--tmpfs", "/tmp") {
		t.Error("missing --tmpfs /tmp")
	}
	if !hasSequence(args, "--tmpfs", "/run") {
		t.Error("missing --tmpfs /run")
	}

	usersIdx := sequenceIndex(args, "--dir", "/Users", "--bind", filepath.Join(fuseRoot, "Users"), "/Users")
	if usersIdx == -1 {
		t.Fatal("missing /Users client bind")
	}
	if usersIdx < runtimeIdx {
		t.Error("client roots should mount after the runtime roots")
	}

	if !hasSequence(args, "--dir", "/private", "--bind", filepath.Join(fuseRoot, "private"), "/private") {
		t.Error("missing /private client bind")
	}
	if !hasSequence(args, "--dir", "/var", "--bind", filepath.Join(fuseRoot, "var"), "/var") {
		t.Error("missing /var client bind")
	}
	if !hasSequence(args, "--dir", "/sys", "--bind", filepath.Join(fuseRoot, "sys"), "/sys") {
		t.Error("missing /sys client bind")
	}
	if hasSequence(args, "--symlink", "private/etc", "/etc") {
		t.Error("client /etc should not be projected (reserved)")
	}
	if hasSequence(args, "--symlink", "private/tmp", "/tmp") {
		t.Error("client /tmp should not be projected")
	}
	if strings.Contains(full, filepath.Join(fuseRoot, "usr")) {
		t.Error("reserved /usr should not be projected from the client")
	}
	if strings.Contains(full, filepath.Join(fuseRoot, "README")) {
		t.Error("regular files should be ignored")
	}

	etcIdx := sequenceIndex(args, "--ro-bind", "/etc", "/etc")
	if etcIdx == -1 {
		t.Fatal("missing server /etc bind")
	}

	credIdx := sequenceIndex(args, "--dir", filepath.Dir("/Users/foo/.config/gh"), "--bind", "/secure/gh", "/Users/foo/.config/gh")
	if credIdx == -1 {
		t.Error("missing credential bind mount")
	}
	if credIdx < usersIdx {
		t.Error("credential mount should come after client roots")
	}

	if !strings.Contains(full, "--chdir /Users/foo/project") {
		t.Error("missing --chdir")
	}

	if args[len(args)-1] != "--" {
		t.Error("args should end with --")
	}
}

func TestBuildBwrapArgsCwdOutsideHome(t *testing.T) {
	fuseRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(fuseRoot, "root"))

	cfg := &SandboxConfig{
		FUSEMountpoint: fuseRoot,
		Cwd:            "/root",
		MountPolicy:    MountPolicyIdentity,
	}

	args := BuildBwrapArgs(cfg)
	if !hasSequence(args, "--dir", "/root", "--bind", filepath.Join(fuseRoot, "root"), "/root") {
		t.Error("missing /root client bind")
	}

	if !hasSequence(args, "--chdir", "/root") {
		t.Error("missing --chdir /root")
	}
}

func TestListClientRootEntriesFiltersDirsAndSymlinks(t *testing.T) {
	fuseRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(fuseRoot, "Users"))
	mustSymlink(t, "Users", filepath.Join(fuseRoot, "home"))
	mustWriteFile(t, filepath.Join(fuseRoot, "hosts"), []byte("skip files"))

	entries := listClientRootEntries(fuseRoot)
	if len(entries) != 2 {
		t.Fatalf("expected 2 root entries, got %d", len(entries))
	}
	if entries[0].Name != "Users" || entries[0].Kind != entryDir {
		t.Fatalf("expected Users directory entry, got %+v", entries[0])
	}
	if entries[1].Name != "home" || entries[1].Kind != entrySymlink || entries[1].LinkTarget != "Users" {
		t.Fatalf("expected home symlink entry, got %+v", entries[1])
	}
}

func TestWrapCommand(t *testing.T) {
	cfg := &SandboxConfig{
		FUSEMountpoint: "/mnt/fuse-local",
		Cwd:            "/home/foo",
		MountPolicy:    MountPolicyIdentity,
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
	secureDir := t.TempDir()
	specs := []config.MountSpec{
		{Name: "gh", Target: "~/.config/gh"},
	}
	mounts := ResolveCredentials(secureDir, specs, "/Users/foo")
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	expectedSource := filepath.Join(secureDir, "gh")
	if mounts[0].Source != expectedSource {
		t.Errorf("expected source %s, got %s", expectedSource, mounts[0].Source)
	}

	expectedTarget := "/Users/foo/.config/gh"
	if mounts[0].Target != expectedTarget {
		t.Errorf("expected target %s, got %s", expectedTarget, mounts[0].Target)
	}
	if mounts[0].ReadOnly {
		t.Error("credential mounts should be writable by default")
	}

	// Empty specs returns nil
	if mounts := ResolveCredentials(secureDir, nil, "/Users/foo"); mounts != nil {
		t.Error("expected nil for empty specs")
	}
}

func TestExpandHomeFallsBackToCurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip("cannot determine current user")
	}
	got := expandHome("~/.config/gh", "")
	want := filepath.Join(u.HomeDir, ".config/gh")
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestValidMountName(t *testing.T) {
	rejected := []string{"", ".", "..", "foo/bar", "foo\\bar"}
	for _, name := range rejected {
		if validMountName(name) {
			t.Errorf("expected %q to be rejected", name)
		}
	}
	accepted := []string{"gh", "gh-hosts.yml", "aws", "kubectl"}
	for _, name := range accepted {
		if !validMountName(name) {
			t.Errorf("expected %q to be accepted", name)
		}
	}
}

func hasSequence(args []string, seq ...string) bool {
	return sequenceIndex(args, seq...) >= 0
}

func sequenceIndex(args []string, seq ...string) int {
	if len(seq) == 0 || len(seq) > len(args) {
		return -1
	}
	for i := 0; i <= len(args)-len(seq); i++ {
		match := true
		for j := range seq {
			if args[i+j] != seq[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s -> %s: %v", path, target, err)
	}
}

func mustWriteFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestBuildBwrapArgsLocalPolicy(t *testing.T) {
	fuseRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(fuseRoot, "Users", "foo", "project"))

	cfg := &SandboxConfig{
		FUSEMountpoint: fuseRoot,
		Credentials: []BindMount{
			{Source: "/secure/gh", Target: "/Users/foo/.config/gh", ReadOnly: false},
		},
		Cwd:         "/Users/foo/project",
		MountPolicy: MountPolicyLocal,
		Home:        "/Users/foo",
	}

	args := BuildBwrapArgs(cfg)
	full := strings.Join(args, " ")

	// Single /local bind
	if !hasSequence(args, "--dir", "/local", "--bind", fuseRoot, "/local") {
		t.Fatal("missing /local bind mount")
	}

	// No identity-style root scanning
	if strings.Contains(full, "--bind "+filepath.Join(fuseRoot, "Users")+" /Users") {
		t.Error("local policy should not project individual top-level dirs")
	}

	// Server /etc
	if !hasSequence(args, "--ro-bind", "/etc", "/etc") {
		t.Error("missing server /etc bind")
	}

	// Credential target prefixed
	if !hasSequence(args, "--dir", "/local/Users/foo/.config", "--bind", "/secure/gh", "/local/Users/foo/.config/gh") {
		t.Error("credential target should be prefixed with /local")
	}

	// CWD prefixed
	if !hasSequence(args, "--chdir", "/local/Users/foo/project") {
		t.Error("cwd should be prefixed with /local")
	}

	// HOME set
	if !hasSequence(args, "--setenv", "HOME", "/local/Users/foo") {
		t.Error("HOME should be set to /local/<home>")
	}

	if args[len(args)-1] != "--" {
		t.Error("args should end with --")
	}
}

func TestBuildBwrapArgsLocalPolicyNoHome(t *testing.T) {
	fuseRoot := t.TempDir()

	cfg := &SandboxConfig{
		FUSEMountpoint: fuseRoot,
		Cwd:            "/work",
		MountPolicy:    MountPolicyLocal,
		Home:           "",
	}

	args := BuildBwrapArgs(cfg)
	for _, a := range args {
		if a == "--setenv" {
			t.Fatal("--setenv should not appear when Home is empty")
		}
	}
}

func TestBuildBwrapArgsDefaultPolicyIsLocal(t *testing.T) {
	fuseRoot := t.TempDir()

	cfg := &SandboxConfig{
		FUSEMountpoint: fuseRoot,
		Cwd:            "/work",
	}

	args := BuildBwrapArgs(cfg)
	if !hasSequence(args, "--dir", "/local", "--bind", fuseRoot, "/local") {
		t.Fatal("zero-value MountPolicy should use local policy")
	}
}

func TestWrapCommandLocalPolicy(t *testing.T) {
	cfg := &SandboxConfig{
		FUSEMountpoint: "/mnt/fuse-local",
		Cwd:            "/home/foo",
		MountPolicy:    MountPolicyLocal,
	}

	wrapped := cfg.WrapCommand([]string{"gh", "pr", "list"})
	if wrapped[0] != "bwrap" {
		t.Error("first arg should be bwrap")
	}
	tail := wrapped[len(wrapped)-3:]
	if tail[0] != "gh" || tail[1] != "pr" || tail[2] != "list" {
		t.Errorf("expected [gh pr list], got %v", tail)
	}
}
