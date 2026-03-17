package main

import (
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

	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

func main() {
	listenAddr := flag.String("listen", ":9022", "address to listen on")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS key file")
	caFile := flag.String("ca", "", "CA certificate for client verification")
	fuseMountBase := flag.String("fuse-mount", "/tmp/cli-box-fuse", "base directory for per-session FUSE mounts")
	sandbox := flag.Bool("sandbox", true, "enable bwrap sandbox")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

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
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	var wg sync.WaitGroup
	go func() {
		<-stop
		logger.Info("shutting down")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				wg.Wait()
				return
			default:
			}
			logger.Error("accept failed", "error", err)
			continue
		}

		wg.Go(func() {
			handleConnection(conn, *fuseMountBase, *sandbox, logger)
		})
	}
}

// handleConnection manages the full lifecycle of a single client connection:
// yamux → FUSE mount → register services → serve → teardown.
func handleConnection(conn net.Conn, fuseMountBase string, sandboxEnabled bool, logger *slog.Logger) {
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

	// Register Command service with sandbox config
	cmdServer := &CommandServer{
		sandboxEnabled: sandboxEnabled,
	}
	pb.RegisterCommandServer(peer.GRPCServer, cmdServer)

	// Serve until the connection closes
	peer.Serve()

	logger.Info("connection closed", "remote", remoteAddr)
}
