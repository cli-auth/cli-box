package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/samber/oops"
)

type SetupCmd struct {
	CLIs []string `arg:"" name:"cli" help:"CLI names to symlink through cli-box." required:""`
}

type RemoveCmd struct {
	CLIs []string `arg:"" name:"cli" help:"Managed CLI names to remove." required:""`
}

type ListCmd struct{}

type StatusCmd struct{}

// stubBinDir returns the directory for CLI symlinks (~/.local/bin by default).
func stubBinDir() string {
	if d := os.Getenv("CLI_BOX_BIN_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "bin")
}

// stubBinaryPath returns the path to the cli-box binary itself.
func stubBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func (cmd *SetupCmd) Run() error {
	binDir := stubBinDir()
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return oops.In("client").Wrapf(err, "create bin dir")
	}

	target, err := stubBinaryPath()
	if err != nil {
		return oops.In("client").Wrapf(err, "resolve self")
	}

	for _, name := range cmd.CLIs {
		link := filepath.Join(binDir, name)

		// Remove existing symlink if it points to us
		if existing, err := os.Readlink(link); err == nil {
			resolved, _ := filepath.EvalSymlinks(link)
			if resolved == target || existing == target {
				fmt.Printf("  %s: already set up\n", name)
				continue
			}
			fmt.Fprintf(os.Stderr, "  %s: %s exists and points to %s (skipped)\n", name, link, existing)
			continue
		}

		if err := os.Symlink(target, link); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", name, err)
			continue
		}
		fmt.Printf("  %s -> %s\n", link, target)
	}
	return nil
}

func (cmd *RemoveCmd) Run() error {
	binDir := stubBinDir()
	target, err := stubBinaryPath()
	if err != nil {
		return oops.In("client").Wrapf(err, "resolve self")
	}

	for _, name := range cmd.CLIs {
		link := filepath.Join(binDir, name)
		resolved, err := filepath.EvalSymlinks(link)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: not found\n", name)
			continue
		}
		if resolved != target {
			fmt.Fprintf(os.Stderr, "  %s: not managed by cli-box (points to %s)\n", name, resolved)
			continue
		}
		os.Remove(link)
		fmt.Printf("  %s: removed\n", name)
	}
	return nil
}

func (cmd *ListCmd) Run() error {
	binDir := stubBinDir()
	target, err := stubBinaryPath()
	if err != nil {
		return oops.In("client").Wrapf(err, "resolve self")
	}

	entries, err := os.ReadDir(binDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cli-box: no managed CLIs")
		return nil
	}

	found := false
	for _, e := range entries {
		link := filepath.Join(binDir, e.Name())
		resolved, err := filepath.EvalSymlinks(link)
		if err != nil {
			continue
		}
		if resolved == target && e.Name() != "cli-box" {
			fmt.Printf("  %s\n", e.Name())
			found = true
		}
	}
	if !found {
		fmt.Fprintln(os.Stderr, "cli-box: no managed CLIs")
	}
	return nil
}

func (cmd *StatusCmd) Run() error {
	return oops.In("client").Errorf("status not yet implemented (requires config)")
}
