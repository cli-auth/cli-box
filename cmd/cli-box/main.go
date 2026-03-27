package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	name := filepath.Base(os.Args[0])
	exe, _ := os.Executable()
	if name == filepath.Base(exe) {
		os.Exit(runManage())
	} else {
		os.Exit(runRemoteCLI(name))
	}
}

type ManageCLI struct {
	Pair    PairCmd    `cmd:"" help:"Pair with a remote cli-box-server."`
	Ping    PingCmd    `cmd:"" help:"Test connection to the paired cli-box-server."`
	Add     AddCmd     `cmd:"" help:"Create symlinks for the given CLIs."`
	Remove  RemoveCmd  `cmd:"" help:"Remove symlinks for the given CLIs."`
	List    ListCmd    `cmd:"" help:"List managed CLI symlinks."`
	Version VersionCmd `cmd:"" help:"Print version."`
}

type VersionCmd struct{}

func (cmd *VersionCmd) Run() error {
	fmt.Printf("cli-box %s\n", version)
	return nil
}

func runManage() int {
	var cli ManageCLI
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "--help")
	}

	ctx := kong.Parse(
		&cli,
		kong.Name("cli-box"),
		kong.Description("Manage cli-box pairing and local CLI shims."),
		kong.UsageOnError(),
	)
	if err := ctx.Run(); err != nil {
		ctx.Errorf("%v", err)
		return 1
	}
	return 0
}
