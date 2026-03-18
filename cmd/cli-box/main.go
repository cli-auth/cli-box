package main

import (
	"fmt"
	"os"
	"path/filepath"
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

func runManage() int {
	if len(os.Args) < 2 {
		printUsage()
		return 1
	}

	switch os.Args[1] {
	case "pair":
		return cmdPair(os.Args[2:])
	case "setup":
		return cmdSetup(os.Args[2:])
	case "remove":
		return cmdRemove(os.Args[2:])
	case "list":
		return cmdList()
	case "status":
		return cmdStatus()
	default:
		fmt.Fprintf(os.Stderr, "cli-box: unknown command %q\n", os.Args[1])
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: cli-box <command>

Commands:
  pair <host:port>  Pair with a remote cli-box-server
  setup <cli...>    Create symlinks for the given CLIs
  remove <cli...>   Remove symlinks for the given CLIs
  list              List managed CLI symlinks
  status            Show connection status to remote`)
}
