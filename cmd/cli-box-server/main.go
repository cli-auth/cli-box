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
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hashicorp/yamux"

	"github.com/cli-auth/cli-box/pkg/config"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

func main() {
	// Handle dump-config before flag parsing
	if len(os.Args) > 1 && os.Args[1] == "dump-config" {
		fmt.Print(config.DefaultTOML())
		return
	}

	listenAddr := flag.String("listen", ":9022", "address to listen on")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS key file")
	caFile := flag.String("ca", "", "CA certificate for client verification")
	fuseMountBase := flag.String("fuse-mount", "/tmp/cli-box-fuse", "base directory for per-session FUSE mounts")
	sandbox := flag.Bool("sandbox", true, "enable bwrap sandbox")
	configPath := flag.String("config", "", "path to TOML config file (uses built-in defaults if not set)")
	flag.Parse()

	logLevel := slog.LevelInfo
	if os.Getenv("CLI_BOX_DEBUG") != "" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	var cfg *config.Config
	if *configPath != "" {
		var err error
		cfg, err = config.Load(*configPath)
		if err != nil {
			logger.Error("config load failed", "path", *configPath, "error", err)
			os.Exit(1)
		}
	} else {
		var err error
		cfg, err = config.LoadDefault()
		if err != nil {
			logger.Error("default config parse failed", "error", err)
			os.Exit(1)
		}
	}

	var tlsCfg *tls.Config
	if *certFile != "" && *keyFile != "" && *caFile != "" {
		var err error
		tlsCfg, err = transport.LoadServerTLS(*certFile, *keyFile, *caFile)
		if err != nil {
			logger.Error("TLS setup failed", "error", err)
			os.Exit(1)
		}
	}

	var ln net.Listener
	var err error
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
			handleConnection(ctx, conn, *fuseMountBase, *sandbox, cfg, logger)
		})
	}
}

// handleConnection manages the full lifecycle of a single client connection:
// yamux → FUSE mount → register services → serve → teardown.
func handleConnection(ctx context.Context, conn net.Conn, fuseMountBase string, sandboxEnabled bool, cfg *config.Config, logger *slog.Logger) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	logger.Info("connection accepted", "remote", remoteAddr)

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

	// Create per-session FUSE mount directory
	mountpoint := filepath.Join(fuseMountBase, fmt.Sprintf("session-%d", os.Getpid()))
	os.MkdirAll(mountpoint, 0o700)
	defer os.Remove(mountpoint)

	// Register Command service before serving so it's available immediately.
	// Exec handlers block on fuseReady until the FUSE mount is up.
	fuseReady := make(chan struct{})
	cmdServer := &CommandServer{
		ctx:            ctx,
		logger:         logger,
		fuseMountpoint: mountpoint,
		sandboxEnabled: sandboxEnabled,
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
