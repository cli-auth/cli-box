package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/samber/oops"

	"github.com/cli-auth/cli-box/pkg/policy"
)

type MountPolicy string

const (
	MountPolicyLocal    MountPolicy = "local"
	MountPolicyIdentity MountPolicy = "identity"
)

const localMountRoot = "/local"

// SandboxConfig holds the bubblewrap sandbox configuration for a command execution.
type SandboxConfig struct {
	FUSEMountpoint string
	Credentials    []BindMount
	ExtraMounts    []BindMount
	Cwd            string
	MountPolicy    MountPolicy
	Home           string
}

type BindMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type entryKind int

const (
	entryDir entryKind = iota
	entrySymlink
)

type RootEntry struct {
	Name       string
	SourcePath string
	LinkTarget string
	Kind       entryKind
}

var reservedClientPaths = map[string]bool{
	"/usr":   true,
	"/bin":   true,
	"/sbin":  true,
	"/lib":   true,
	"/lib64": true,
	"/proc":  true,
	"/dev":   true,
	"/etc":   true,
	"/run":   true,
	"/tmp":   true,
}

// WrapCommand prepends bwrap arguments to the given command.
func (sc *SandboxConfig) WrapCommand(args []string) []string {
	return append(BuildBwrapArgs(sc), args...)
}

// BuildBwrapArgs keeps the Linux runtime owned by the server while projecting
// the client's filesystem layout into the namespace.
func BuildBwrapArgs(cfg *SandboxConfig) []string {
	args := []string{"bwrap", "--tmpfs", "/"}

	args = append(args, runtimeMountArgs()...)
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run")
	args = append(args, "--ro-bind", "/etc", "/etc")

	switch cfg.MountPolicy {
	case MountPolicyIdentity:
		args = append(args, buildIdentityMounts(cfg)...)
	default: // MountPolicyLocal and zero value
		args = append(args, buildLocalMounts(cfg)...)
	}

	args = append(args, "--")
	return args
}

// buildIdentityMounts projects client top-level dirs at their original paths.
func buildIdentityMounts(cfg *SandboxConfig) []string {
	var args []string

	for _, entry := range listClientRootEntries(cfg.FUSEMountpoint) {
		target := "/" + entry.Name
		if reservedClientPaths[target] {
			continue
		}
		switch entry.Kind {
		case entryDir:
			args = append(args, "--dir", target, "--bind", entry.SourcePath, target)
		case entrySymlink:
			args = append(args, "--symlink", entry.LinkTarget, target)
		}
	}

	args = appendCredentialMounts(args, cfg.Credentials, "")
	args = appendExtraMounts(args, cfg.ExtraMounts, "")

	if cfg.Cwd != "" {
		args = append(args, "--chdir", cfg.Cwd)
	}

	return args
}

// buildLocalMounts mounts the entire FUSE tree under /local.
func buildLocalMounts(cfg *SandboxConfig) []string {
	var args []string

	args = append(args, "--dir", localMountRoot, "--bind", cfg.FUSEMountpoint, localMountRoot)

	args = appendCredentialMounts(args, cfg.Credentials, localMountRoot)
	args = appendExtraMounts(args, cfg.ExtraMounts, localMountRoot)

	if cfg.Cwd != "" {
		args = append(args, "--chdir", filepath.Join(localMountRoot, cfg.Cwd))
	}

	if cfg.Home != "" {
		args = append(args, "--setenv", "HOME", filepath.Join(localMountRoot, cfg.Home))
	}

	return args
}

func appendCredentialMounts(args []string, creds []BindMount, prefix string) []string {
	for _, c := range creds {
		flag := "--bind"
		if c.ReadOnly {
			flag = "--ro-bind"
		}
		target := filepath.Join(prefix, c.Target)
		args = append(args, "--dir", filepath.Dir(target), flag, c.Source, target)
	}
	return args
}

func appendExtraMounts(args []string, mounts []BindMount, prefix string) []string {
	for _, m := range mounts {
		flag := "--bind"
		if m.ReadOnly {
			flag = "--ro-bind"
		}
		target := filepath.Join(prefix, m.Target)
		args = append(args, "--dir", filepath.Dir(target), flag, m.Source, target)
	}
	return args
}

var runtimeMountArgs = sync.OnceValue(func() []string {
	var args []string
	for _, p := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		switch {
		case info.IsDir():
			args = append(args, "--ro-bind", p, p)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				continue
			}
			args = append(args, "--symlink", target, p)
		}
	}
	return args
})

func listClientRootEntries(fuseMountpoint string) []RootEntry {
	entries, err := os.ReadDir(fuseMountpoint)
	if err != nil {
		return nil
	}

	var roots []RootEntry
	for _, entry := range entries {
		sourcePath := filepath.Join(fuseMountpoint, entry.Name())
		modeType := entry.Type()
		switch {
		case entry.IsDir():
			roots = append(roots, RootEntry{
				Name:       entry.Name(),
				SourcePath: sourcePath,
				Kind:       entryDir,
			})
		case modeType&os.ModeSymlink != 0:
			linkTarget, err := os.Readlink(sourcePath)
			if err != nil {
				continue
			}
			roots = append(roots, RootEntry{
				Name:       entry.Name(),
				SourcePath: sourcePath,
				LinkTarget: linkTarget,
				Kind:       entrySymlink,
			})
		}
	}
	return roots
}

// ResolveManagedCredentialMounts resolves secureDir-backed credential mounts.
func ResolveManagedCredentialMounts(secureDir string, mounts []policy.ManagedCredentialMount) ([]BindMount, error) {
	var result []BindMount
	for _, m := range mounts {
		if !validMountName(m.Store) {
			return nil, oops.In("exec").Errorf("credential store %q must be a plain name", m.Store)
		}
		source := filepath.Join(secureDir, m.Store)
		if _, err := os.Stat(source); err != nil {
			if m.File {
				if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
					return nil, oops.In("exec").Wrapf(err, "prepare credential store %q", m.Store)
				}
				if err := os.WriteFile(source, nil, 0o600); err != nil {
					return nil, oops.In("exec").Wrapf(err, "prepare credential store %q", m.Store)
				}
			} else {
				if err := os.MkdirAll(source, 0o700); err != nil {
					return nil, oops.In("exec").Wrapf(err, "prepare credential store %q", m.Store)
				}
			}
		}
		result = append(result, BindMount{
			Source:   source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		})
	}
	return result, nil
}

// validMountName rejects path traversal: name must be a plain filename
// with no slashes, no ".." component, and not empty.
func validMountName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	return true
}

// NewSandboxConfig creates a sandbox configuration for executing the given CLI.
func NewSandboxConfig(fuseMountpoint, cwd, home string, policy MountPolicy) *SandboxConfig {
	// Sanitize client-supplied paths to prevent traversal attacks.
	cwd = filepath.Clean("/" + cwd)
	if home != "" {
		home = filepath.Clean("/" + home)
	}

	return &SandboxConfig{
		FUSEMountpoint: fuseMountpoint,
		Cwd:            cwd,
		MountPolicy:    policy,
		Home:           home,
	}
}

// FormatBwrapCommand returns the full bwrap command as a string for debugging.
func FormatBwrapCommand(cfg *SandboxConfig, args []string) string {
	return strings.Join(cfg.WrapCommand(args), " ")
}
