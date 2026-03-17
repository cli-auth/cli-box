package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/hashicorp/yamux"
	"golang.org/x/term"

	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

type termWriter struct {
	w   io.Writer
	raw atomic.Bool
}

func (t *termWriter) Write(p []byte) (int, error) {
	n := len(p)
	if t.raw.Load() {
		p = bytes.ReplaceAll(p, []byte("\n"), []byte("\r\n"))
	}
	_, err := t.w.Write(p)
	return n, err
}

var termW = &termWriter{w: os.Stderr}

var logger = func() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("CLI_BOX_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(termW, &slog.HandlerOptions{Level: level}))
}()

// runRemoteCLI connects to the remote server, registers the local FileSystem
// service, and executes the CLI command remotely, streaming I/O back and forth.
func runRemoteCLI(cliName string) int {
	cfg, err := loadStubConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box: %v\n", err)
		return 1
	}

	logger.Debug("connecting", "addr", cfg.ServerAddr)

	var conn net.Conn
	if cfg.TLS != nil {
		conn, err = tls.Dial("tcp", cfg.ServerAddr, cfg.TLS)
	} else {
		conn, err = net.Dial("tcp", cfg.ServerAddr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box: connect to %s: %v\n", cfg.ServerAddr, err)
		return 1
	}
	defer conn.Close()
	logger.Debug("connected")

	session, err := yamux.Client(conn, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box: yamux: %v\n", err)
		return 1
	}
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box: peer: %v\n", err)
		return 1
	}

	// Register local FileSystem service so the remote can access our files
	cwd, _ := os.Getwd()
	pb.RegisterFileSystemServer(peer.GRPCServer, NewFSServer("/"))
	go peer.Serve()
	defer peer.Close()

	// Open bidirectional Exec stream
	cmdClient := pb.NewCommandClient(peer.ClientConn)
	stream, err := cmdClient.Exec(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cli-box: exec: %v\n", err)
		return 1
	}

	isTTY := term.IsTerminal(int(os.Stdin.Fd()))

	startMsg := &pb.ExecStart{
		Args: append([]string{cliName}, os.Args[1:]...),
		Cwd:  cwd,
		Tty:  isTTY,
	}

	if isTTY {
		w, h, _ := term.GetSize(int(os.Stdin.Fd()))
		startMsg.WindowSize = &pb.WindowSize{
			Rows: uint32(h),
			Cols: uint32(w),
		}
	}

	// Pass through relevant environment variables
	startMsg.Env = filterEnv()

	logger.Debug("exec", "args", startMsg.Args, "cwd", startMsg.Cwd, "tty", startMsg.Tty)

	if err := stream.Send(&pb.ExecInput{Input: &pb.ExecInput_Start{Start: startMsg}}); err != nil {
		fmt.Fprintf(os.Stderr, "cli-box: send start: %v\n", err)
		return 1
	}
	logger.Debug("start message sent")

	// Put terminal in raw mode if TTY
	if isTTY {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			termW.raw.Store(true)
			defer func() {
				termW.raw.Store(false)
				term.Restore(int(os.Stdin.Fd()), oldState)
			}()
		}
	}

	// Forward signals and window size changes
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGWINCH)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGWINCH:
				if isTTY {
					w, h, _ := term.GetSize(int(os.Stdin.Fd()))
					stream.Send(&pb.ExecInput{
						Input: &pb.ExecInput_Resize{Resize: &pb.WindowSize{
							Rows: uint32(h),
							Cols: uint32(w),
						}},
					})
				}
			default:
				sigNum := sig.(syscall.Signal)
				stream.Send(&pb.ExecInput{
					Input: &pb.ExecInput_Signal{Signal: &pb.Signal{Signum: int32(sigNum)}},
				})
			}
		}
	}()

	// Stream stdin to remote
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				stream.Send(&pb.ExecInput{
					Input: &pb.ExecInput_Stdin{Stdin: data},
				})
			}
			if err != nil {
				return
			}
		}
	}()

	// Receive output from remote
	logger.Debug("waiting for output")
	var exitCode int32
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				logger.Debug("recv EOF")
				break
			}
			logger.Error("recv", "error", err)
			return 1
		}
		switch v := msg.Output.(type) {
		case *pb.ExecOutput_Stdout:
			logger.Debug("recv stdout", "bytes", len(v.Stdout))
			os.Stdout.Write(v.Stdout)
		case *pb.ExecOutput_Stderr:
			logger.Debug("recv stderr", "bytes", len(v.Stderr))
			os.Stderr.Write(v.Stderr)
		case *pb.ExecOutput_Exit:
			logger.Debug("recv exit", "code", v.Exit.ExitCode)
			exitCode = v.Exit.ExitCode
			signal.Stop(sigCh)
			return int(exitCode)
		}
	}

	return int(exitCode)
}

type stubConfig struct {
	ServerAddr string
	TLS        *tls.Config
}

func loadStubConfig() (*stubConfig, error) {
	addr := os.Getenv("CLI_BOX_SERVER")
	if addr == "" {
		return nil, fmt.Errorf("CLI_BOX_SERVER not set (set to host:port of cli-box-server)")
	}

	cfg := &stubConfig{ServerAddr: addr}

	certFile := os.Getenv("CLI_BOX_CERT")
	keyFile := os.Getenv("CLI_BOX_KEY")
	caFile := os.Getenv("CLI_BOX_CA")

	if certFile != "" && keyFile != "" && caFile != "" {
		tlsCfg, err := transport.LoadClientTLS(certFile, keyFile, caFile)
		if err != nil {
			return nil, fmt.Errorf("TLS: %w", err)
		}
		cfg.TLS = tlsCfg
	}

	return cfg, nil
}

func filterEnv() map[string]string {
	passthrough := []string{
		"HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL",
		"PATH", "EDITOR", "VISUAL", "PAGER",
		"NO_COLOR", "FORCE_COLOR", "CLICOLOR",
	}
	env := make(map[string]string)
	for _, key := range passthrough {
		if val, ok := os.LookupEnv(key); ok {
			env[key] = val
		}
	}
	return env
}
