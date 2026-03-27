package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/samber/oops"
)

type AddCmd struct {
	BinDir string   `short:"d" env:"CLI_BOX_BIN_DIR" help:"Directory for CLI symlinks (default: same dir as cli-box)." type:"path"`
	CLIs   []string `arg:"" name:"cli" help:"CLI names to symlink through cli-box." required:""`
}

type RemoveCmd struct {
	BinDir string   `short:"d" env:"CLI_BOX_BIN_DIR" help:"Directory where CLI symlinks were installed." type:"path"`
	All    bool     `short:"a" help:"Remove all managed CLI symlinks."`
	CLIs   []string `arg:"" name:"cli" help:"Managed CLI names to remove." optional:""`
}

type ListCmd struct {
	BinDir string `short:"d" env:"CLI_BOX_BIN_DIR" help:"Directory to scan for managed CLI symlinks." type:"path"`
}

// stubBinDir returns the directory for CLI symlinks. Falls back to the
// directory containing the cli-box binary so shims are guaranteed to be in PATH.
func stubBinDir(override string) string {
	if override != "" {
		return override
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
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

// isDirInPATH reports whether dir appears in the current PATH.
func isDirInPATH(dir string) bool {
	clean := filepath.Clean(dir)
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.Clean(p) == clean {
			return true
		}
	}
	return false
}

func (cmd *AddCmd) Run() error {
	binDir := stubBinDir(cmd.BinDir)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return oops.In("client").Wrapf(err, "create bin dir")
	}

	target, err := stubBinaryPath()
	if err != nil {
		return oops.In("client").Wrapf(err, "resolve self")
	}

	for _, name := range cmd.CLIs {
		link := filepath.Join(binDir, name)

		// Skip if symlink already points to us
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

	if !isDirInPATH(binDir) {
		fmt.Fprintf(os.Stderr, "  hint: %s is not in PATH. Add it:\n    export PATH=\"$PATH:%s\"\n", binDir, binDir)
	}
	return nil
}

func (cmd *RemoveCmd) Run() error {
	if !cmd.All && len(cmd.CLIs) == 0 {
		return oops.In("client").Errorf("specify CLI names or use --all")
	}

	binDir := stubBinDir(cmd.BinDir)
	target, err := stubBinaryPath()
	if err != nil {
		return oops.In("client").Wrapf(err, "resolve self")
	}

	names := cmd.CLIs
	if cmd.All {
		entries, err := os.ReadDir(binDir)
		if err != nil {
			return nil // nothing to remove
		}
		for _, e := range entries {
			link := filepath.Join(binDir, e.Name())
			resolved, err := filepath.EvalSymlinks(link)
			if err != nil {
				continue
			}
			if resolved == target && e.Name() != filepath.Base(target) {
				names = append(names, e.Name())
			}
		}
	}

	for _, name := range names {
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
	binDir := stubBinDir(cmd.BinDir)
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
		if resolved == target && e.Name() != filepath.Base(target) {
			fmt.Printf("  %s\n", e.Name())
			found = true
		}
	}
	if !found {
		fmt.Fprintln(os.Stderr, "cli-box: no managed CLIs")
	}
	return nil
}
