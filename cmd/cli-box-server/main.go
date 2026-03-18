package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/hashicorp/yamux"

	"github.com/cli-auth/cli-box/pkg/config"
	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

type CLI struct {
	Serve      ServeCmd      `cmd:"" help:"Run the cli-box server."`
	Init       InitCmd       `cmd:"" help:"Initialize PKI state."`
	AddClient  AddClientCmd  `cmd:"" name:"add-client" help:"Mint a one-time pairing token."`
	DumpConfig DumpConfigCmd `cmd:"" name:"dump-config" help:"Print the default TOML config."`
}

type ServeCmd struct {
	Listen        string `help:"Address to listen on." default:":9443"`
	StateDir      string `help:"PKI state directory." default:"./state"`
	FuseMountBase string `help:"Base directory for per-session FUSE mounts." default:"/tmp/cli-box-fuse"`
	Sandbox       bool   `help:"Enable bwrap sandbox." default:"true"`
	SecureDir     string `help:"Base directory for per-CLI credential stores." default:"./secure"`
	ConfigPath    string `name:"config" help:"Path to TOML config file. Uses built-in defaults if not set."`
}

func main() {
	var cli CLI
	ctx := kong.Parse(
		&cli,
		kong.Name(filepath.Base(os.Args[0])),
		kong.Description("Run cli-box-server or manage its local PKI state."),
		kong.UsageOnError(),
	)
	ctx.FatalIfErrorf(ctx.Run())
}

func (cmd *ServeCmd) Run() error {
	return runServe(*cmd)
}

func (cmd *DumpConfigCmd) Run() error {
	fmt.Print(config.DefaultTOML())
	return nil
}

func runServe(cmd ServeCmd) error {
	logLevel := slog.LevelInfo
	if os.Getenv("CLI_BOX_DEBUG") != "" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	var (
		cfg *config.Config
		err error
	)
	if cmd.ConfigPath != "" {
		cfg, err = config.Load(cmd.ConfigPath)
	} else {
		cfg, err = config.LoadDefault()
	}
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}

	var tlsCfg *tls.Config
	var pairingState *PairingState

	if cmd.StateDir != "" {
		caCert, caKey, serverCert, serverKey, err := pki.LoadState(cmd.StateDir)
		if err != nil {
			return fmt.Errorf("load PKI state failed: %w", err)
		}
		tlsCfg, err = transport.LoadServerTLSDualMode(serverCert, serverKey, caCert)
		if err != nil {
			return fmt.Errorf("TLS setup failed: %w", err)
		}
		pairingState = &PairingState{
			CACert:   caCert,
			CAKey:    caKey,
			StateDir: cmd.StateDir,
			Limiter:  NewPairingRateLimiter(),
		}
	}

	var ln net.Listener
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", cmd.Listen, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", cmd.Listen)
	}
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	defer ln.Close()

	if err := os.MkdirAll(cmd.FuseMountBase, 0o700); err != nil {
		return fmt.Errorf("fuse mount base setup failed: %w", err)
	}

	logger.Info("listening", "addr", ln.Addr())

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			default:
			}
			logger.Error("accept failed", "error", err)
			continue
		}

		wg.Go(func() {
			handleConnection(ctx, conn, cmd.FuseMountBase, cmd.Sandbox, cmd.SecureDir, cfg, pairingState, logger)
		})
	}
}

// handleConnection manages the full lifecycle of a single client connection:
// yamux → FUSE mount → register services → serve → teardown.
// If pairingState is set and the client has no certificate, it gets a pairing-only session.
func handleConnection(ctx context.Context, conn net.Conn, fuseMountBase string, sandboxEnabled bool, secureDir string, cfg *config.Config, pairingState *PairingState, logger *slog.Logger) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	logger.Info("connection accepted", "remote", remoteAddr)

	// Branch on client cert presence for dual-mode TLS
	if pairingState != nil {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				logger.Error("TLS handshake failed", "error", err, "remote", remoteAddr)
				return
			}
			if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
				logger.Info("unauthenticated connection, entering pairing mode", "remote", remoteAddr)
				session, err := yamux.Server(conn, nil)
				if err != nil {
					logger.Error("yamux setup failed (pairing)", "error", err, "remote", remoteAddr)
					return
				}
				handlePairingSession(ctx, session, pairingState, logger)
				return
			}
		}
	}

	session, err := yamux.Server(conn, nil)
	if err != nil {
		logger.Error("yamux setup failed", "error", err, "remote", remoteAddr)
		return
	}
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		logger.Error("peer setup failed", "error", err, "remote", remoteAddr)
		return
	}
	defer peer.Close()

	mountpoint, err := os.MkdirTemp(fuseMountBase, "session-")
	if err != nil {
		logger.Error("fuse mount directory setup failed", "error", err, "base", fuseMountBase)
		return
	}
	defer os.Remove(mountpoint)

	// Register Command service before serving so it's available immediately.
	// Exec handlers block on fuseReady until the FUSE mount is up.
	fuseReady := make(chan struct{})
	cmdServer := &CommandServer{
		ctx:            ctx,
		logger:         logger,
		fuseMountpoint: mountpoint,
		sandboxEnabled: sandboxEnabled,
		secureDir:      secureDir,
		config:         cfg,
		fuseReady:      fuseReady,
	}
	pb.RegisterCommandServer(peer.GRPCServer, cmdServer)

	// Start gRPC server so the client can connect and the FUSE
	// layer can reach the client's FileSystem service.
	serveDone := make(chan struct{})
	go func() {
		peer.Serve()
		close(serveDone)
	}()

	// Mount FUSE backed by the client's FileSystem service
	fsClient := pb.NewFileSystemClient(peer.ClientConn)
	fuseServer, err := MountFUSE(mountpoint, fsClient)
	if err != nil {
		logger.Error("FUSE mount failed", "error", err, "mountpoint", mountpoint)
		return
	}
	defer func() {
		if err := UnmountFUSE(fuseServer); err != nil {
			logger.Warn("FUSE unmount failed", "error", err)
		}
	}()

	logger.Info("FUSE mounted", "mountpoint", mountpoint, "remote", remoteAddr)
	close(fuseReady)

	// Block until session closes or server shuts down
	select {
	case <-serveDone:
	case <-ctx.Done():
		logger.Info("shutting down connection", "remote", remoteAddr)
	}

	logger.Info("connection closed", "remote", remoteAddr)
}
