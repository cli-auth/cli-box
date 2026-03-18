package main

import (
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
)

func main() {
	name := filepath.Base(os.Args[0])

	switch name {
	case "cli-box":
		os.Exit(runManage())
	default:
		os.Exit(runRemoteCLI(name))
	}
}

type ManageCLI struct {
	Pair   PairCmd   `cmd:"" help:"Pair with a remote cli-box-server."`
	Setup  SetupCmd  `cmd:"" help:"Create symlinks for the given CLIs."`
	Remove RemoveCmd `cmd:"" help:"Remove symlinks for the given CLIs."`
	List   ListCmd   `cmd:"" help:"List managed CLI symlinks."`
	Status StatusCmd `cmd:"" help:"Show connection status to the remote server."`
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
