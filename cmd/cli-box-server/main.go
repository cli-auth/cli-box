package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/hashicorp/yamux"

	"github.com/cli-auth/cli-box/pkg/config"
	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

func main() {
	// Handle subcommands before flag parsing
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "dump-config":
			fmt.Print(config.DefaultTOML())
			return
		case "init":
			os.Exit(cmdInit(os.Args[2:]))
		case "add-client":
			os.Exit(cmdAddClient(os.Args[2:]))
		}
	}

	listenAddr := flag.String("listen", ":9022", "address to listen on")
	stateDir := flag.String("state-dir", "", "PKI state directory (from cli-box-server init)")
	fuseMountBase := flag.String("fuse-mount", "/tmp/cli-box-fuse", "base directory for per-session FUSE mounts")
	sandbox := flag.Bool("sandbox", true, "enable bwrap sandbox")
	secureDir := flag.String("secure-dir", "./secure", "base directory for per-CLI credential stores")
	configPath := flag.String("config", "", "path to TOML config file (uses built-in defaults if not set)")
	flag.Parse()

	logLevel := slog.LevelInfo
	if os.Getenv("CLI_BOX_DEBUG") != "" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	var cfg *config.Config
	var err error
	if *configPath != "" {
		cfg, err = config.Load(*configPath)
	} else {
		cfg, err = config.LoadDefault()
	}
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}

	var tlsCfg *tls.Config
	var pairingState *PairingState

	if *stateDir != "" {
		caCert, caKey, serverCert, serverKey, err := pki.LoadState(*stateDir)
		if err != nil {
			logger.Error("load PKI state failed", "error", err)
			os.Exit(1)
		}
		tlsCfg, err = transport.LoadServerTLSDualMode(serverCert, serverKey, caCert)
		if err != nil {
			logger.Error("TLS setup failed", "error", err)
			os.Exit(1)
		}
		pairingState = &PairingState{
			CACert:   caCert,
			CAKey:    caKey,
			StateDir: *stateDir,
		}
	}

	var ln net.Listener
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", *listenAddr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", *listenAddr)
	}
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	defer ln.Close()

	if err := os.MkdirAll(*fuseMountBase, 0o700); err != nil {
		logger.Error("fuse mount base setup failed", "error", err)
		os.Exit(1)
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
				return
			default:
			}
			logger.Error("accept failed", "error", err)
			continue
		}

		wg.Go(func() {
			handleConnection(ctx, conn, *fuseMountBase, *sandbox, *secureDir, cfg, pairingState, logger)
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
