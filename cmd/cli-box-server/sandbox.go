package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cli-auth/cli-box/pkg/config"
)

type MountPolicy string

const (
	MountPolicyLocal    MountPolicy = "local"
	MountPolicyIdentity MountPolicy = "identity"
)

const localMountRoot = "/local"

var currentHomeDir = sync.OnceValue(func() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.HomeDir
})

// SandboxConfig holds the bubblewrap sandbox configuration for a command execution.
type SandboxConfig struct {
	FUSEMountpoint string
	Credentials    []BindMount
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

// ResolveCredentials returns bind mounts for the given config mount specs,
// resolving each name against secureDir.
func ResolveCredentials(secureDir string, mounts []config.MountSpec, home string) []BindMount {
	var result []BindMount
	for _, m := range mounts {
		if !validMountName(m.Name) {
			continue
		}
		source := filepath.Join(secureDir, m.Name)
		if _, err := os.Stat(source); err != nil {
			if m.File {
				os.WriteFile(source, nil, 0o600)
			} else {
				os.MkdirAll(source, 0o700)
			}
		}
		result = append(result, BindMount{
			Source:   source,
			Target:   expandHome(m.Target, home),
			ReadOnly: false,
		})
	}
	return result
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

func expandHome(path, home string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	if home != "" {
		return filepath.Join(home, path[2:])
	}
	if h := currentHomeDir(); h != "" {
		return filepath.Join(h, path[2:])
	}
	return path
}

// NewSandboxConfig creates a sandbox configuration for executing the given CLI.
func NewSandboxConfig(cliName, fuseMountpoint, cwd, secureDir, home string, policy MountPolicy, cfg *config.Config) *SandboxConfig {
	// Sanitize client-supplied paths to prevent traversal attacks.
	cwd = filepath.Clean("/" + cwd)
	if home != "" {
		home = filepath.Clean("/" + home)
	}

	var mounts []config.MountSpec
	if cli, ok := cfg.CLI[cliName]; ok {
		mounts = cli.Mounts
	}
	return &SandboxConfig{
		FUSEMountpoint: fuseMountpoint,
		Credentials:    ResolveCredentials(secureDir, mounts, home),
		Cwd:            cwd,
		MountPolicy:    policy,
		Home:           home,
	}
}

// FormatBwrapCommand returns the full bwrap command as a string for debugging.
func FormatBwrapCommand(cfg *SandboxConfig, args []string) string {
	return strings.Join(cfg.WrapCommand(args), " ")
}
