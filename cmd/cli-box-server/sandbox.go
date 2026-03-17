package main

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
)

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
//  1. System paths (ro-bind from host)
//  2. FUSE-backed paths (bind from /mnt/fuse-local)
//  3. Remote overlays (credentials + system files like resolv.conf)
func BuildBwrapArgs(cfg *SandboxConfig) []string {
	args := []string{"bwrap"}

	// 1. System paths from remote host
	for _, p := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		args = append(args, "--ro-bind", p, p)
	}
	args = append(args, "--proc", "/proc")
	args = append(args, "--dev", "/dev")
	args = append(args, "--tmpfs", "/tmp")

	// 2. FUSE-backed client paths
	mnt := cfg.FUSEMountpoint
	args = append(args, "--bind", filepath.Join(mnt, "etc"), "/etc")
	args = append(args, "--bind", filepath.Join(mnt, "home"), "/home")

	// 3. Remote overlays — system files
	args = append(args, "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf")

	// 3. Remote overlays — credentials (per-CLI, mount order matters)
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

// CredentialSpec defines where a CLI's credentials live on the remote
// and where they should appear inside the sandbox.
type CredentialSpec struct {
	Source string
	Target string
}

// KnownCredentials maps CLI names to their credential locations.
// These paths use ~ which gets expanded at runtime.
var KnownCredentials = map[string]CredentialSpec{
	"gh": {
		Source: "/secure/gh",
		Target: "~/.config/gh",
	},
	"aws": {
		Source: "/secure/aws",
		Target: "~/.aws",
	},
	"gcloud": {
		Source: "/secure/gcloud",
		Target: "~/.config/gcloud",
	},
	"kubectl": {
		Source: "/secure/kubectl",
		Target: "~/.kube",
	},
}

// ResolveCredentials returns bind mounts for the given CLI name.
func ResolveCredentials(cliName string) []BindMount {
	spec, ok := KnownCredentials[cliName]
	if !ok {
		return nil
	}
	return []BindMount{{
		Source:   spec.Source,
		Target:   expandHome(spec.Target),
		ReadOnly: true,
	}}
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	u, err := user.Current()
	if err != nil {
		return path
	}
	return filepath.Join(u.HomeDir, path[2:])
}

// NewSandboxConfig creates a sandbox configuration for executing the given CLI.
func NewSandboxConfig(cliName, fuseMountpoint, cwd string) *SandboxConfig {
	return &SandboxConfig{
		FUSEMountpoint: fuseMountpoint,
		Credentials:    ResolveCredentials(cliName),
		Cwd:            cwd,
	}
}

// FormatBwrapCommand returns the full bwrap command as a string for debugging.
func FormatBwrapCommand(cfg *SandboxConfig, args []string) string {
	all := cfg.WrapCommand(args)
	return fmt.Sprintf("%s", strings.Join(all, " "))
}
