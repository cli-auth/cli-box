package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cli-auth/cli-box/pkg/config"
)

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
}

type BindMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type RootEntry struct {
	Name       string
	SourcePath string
	LinkTarget string
	IsDir      bool
	IsSymlink  bool
}

var reservedClientPaths = map[string]bool{
	"/usr":   true,
	"/bin":   true,
	"/sbin":  true,
	"/lib":   true,
	"/lib64": true,
	"/proc":  true,
	"/dev":   true,
	"/run":   true,
	"/tmp":   true,
}

// WrapCommand prepends bwrap arguments to the given command.
func (sc *SandboxConfig) WrapCommand(args []string) []string {
	return append(BuildBwrapArgs(sc), args...)
}

// BuildBwrapArgs keeps the Linux runtime owned by the server while projecting
// the client's filesystem layout into the namespace at matching top-level paths.
func BuildBwrapArgs(cfg *SandboxConfig) []string {
	args := []string{"bwrap", "--tmpfs", "/"}

	args = appendRuntimeMounts(args)
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run")

	for _, entry := range listClientRootEntries(cfg.FUSEMountpoint) {
		target := "/" + entry.Name
		if reservedClientPaths[target] {
			continue
		}
		if entry.IsDir {
			args = append(args, "--dir", target, "--bind", entry.SourcePath, target)
			continue
		}
		if entry.IsSymlink {
			args = append(args, "--symlink", entry.LinkTarget, target)
		}
	}

	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		args = append(args, "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf")
	}

	for _, c := range cfg.Credentials {
		flag := "--bind"
		if c.ReadOnly {
			flag = "--ro-bind"
		}
		args = append(args, "--dir", filepath.Dir(c.Target), flag, c.Source, c.Target)
	}

	// Working directory
	if cfg.Cwd != "" {
		args = append(args, "--chdir", cfg.Cwd)
	}

	args = append(args, "--")
	return args
}

func appendRuntimeMounts(args []string) []string {
	for _, p := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		switch {
		case info.IsDir():
			args = append(args, "--dir", p, "--ro-bind", p, p)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				continue
			}
			args = append(args, "--symlink", target, p)
		}
	}
	return args
}

func listClientRootEntries(fuseMountpoint string) []RootEntry {
	entries, err := os.ReadDir(fuseMountpoint)
	if err != nil {
		return nil
	}

	var roots []RootEntry
	for _, entry := range entries {
		sourcePath := filepath.Join(fuseMountpoint, entry.Name())
		info, err := os.Lstat(sourcePath)
		if err != nil {
			continue
		}
		switch {
		case info.IsDir():
			roots = append(roots, RootEntry{
				Name:       entry.Name(),
				SourcePath: sourcePath,
				IsDir:      true,
			})
		case info.Mode()&os.ModeSymlink != 0:
			linkTarget, err := os.Readlink(sourcePath)
			if err != nil {
				continue
			}
			roots = append(roots, RootEntry{
				Name:       entry.Name(),
				SourcePath: sourcePath,
				LinkTarget: linkTarget,
				IsSymlink:  true,
			})
		}
	}
	return roots
}

// ResolveCredentials returns bind mounts for the given config mount specs,
// resolving each name against secureDir.
func ResolveCredentials(secureDir string, mounts []config.MountSpec) []BindMount {
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
			Target:   expandHome(m.Target),
			ReadOnly: true,
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

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	if home := currentHomeDir(); home != "" {
		return filepath.Join(home, path[2:])
	}
	return path
}

// NewSandboxConfig creates a sandbox configuration for executing the given CLI.
func NewSandboxConfig(cliName, fuseMountpoint, cwd, secureDir string, cfg *config.Config) *SandboxConfig {
	var mounts []config.MountSpec
	if cli, ok := cfg.CLI[cliName]; ok {
		mounts = cli.Mounts
	}
	return &SandboxConfig{
		FUSEMountpoint: fuseMountpoint,
		Credentials:    ResolveCredentials(secureDir, mounts),
		Cwd:            cwd,
	}
}

// FormatBwrapCommand returns the full bwrap command as a string for debugging.
func FormatBwrapCommand(cfg *SandboxConfig, args []string) string {
	all := cfg.WrapCommand(args)
	return fmt.Sprintf("%s", strings.Join(all, " "))
}
