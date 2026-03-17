package main

import (
	"fmt"
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

// WrapCommand prepends bwrap arguments to the given command.
func (sc *SandboxConfig) WrapCommand(args []string) []string {
	return append(BuildBwrapArgs(sc), args...)
}

// BuildBwrapArgs constructs the bwrap argument list per the design doc's mount order:
//  1. FUSE root (full client filesystem as base layer)
//  2. System paths (ro-bind from host, overlay on top)
//  3. Virtual filesystems (proc, dev, tmp)
//  4. Remote overlays (resolv.conf, credentials)
func BuildBwrapArgs(cfg *SandboxConfig) []string {
	args := []string{"bwrap"}

	// 1. Full client filesystem as base layer
	args = append(args, "--bind", cfg.FUSEMountpoint, "/")

	// 2. Host system paths overlay on top so CLIs resolve to server-side binaries
	for _, p := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		args = append(args, "--ro-bind", p, p)
	}

	// 3. Virtual filesystems
	args = append(args, "--proc", "/proc")
	args = append(args, "--dev", "/dev")
	args = append(args, "--tmpfs", "/tmp")

	// 4. Remote overlays — host networking
	args = append(args, "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf")

	// 4. Remote overlays — credentials (per-CLI, mount order matters)
	for _, c := range cfg.Credentials {
		flag := "--bind"
		if c.ReadOnly {
			flag = "--ro-bind"
		}
		args = append(args, flag, c.Source, c.Target)
	}

	// Working directory
	if cfg.Cwd != "" {
		args = append(args, "--chdir", cfg.Cwd)
	}

	args = append(args, "--")
	return args
}

// ResolveCredentials returns bind mounts for the given config mount specs.
func ResolveCredentials(mounts []config.MountSpec) []BindMount {
	var result []BindMount
	for _, m := range mounts {
		result = append(result, BindMount{
			Source:   m.Source,
			Target:   expandHome(m.Target),
			ReadOnly: true,
		})
	}
	return result
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
func NewSandboxConfig(cliName, fuseMountpoint, cwd string, cfg *config.Config) *SandboxConfig {
	var mounts []config.MountSpec
	if cli, ok := cfg.CLI[cliName]; ok {
		mounts = cli.Mounts
	}
	return &SandboxConfig{
		FUSEMountpoint: fuseMountpoint,
		Credentials:    ResolveCredentials(mounts),
		Cwd:            cwd,
	}
}

// FormatBwrapCommand returns the full bwrap command as a string for debugging.
func FormatBwrapCommand(cfg *SandboxConfig, args []string) string {
	all := cfg.WrapCommand(args)
	return fmt.Sprintf("%s", strings.Join(all, " "))
}
