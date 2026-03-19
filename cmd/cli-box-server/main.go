package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/hashicorp/yamux"
	"github.com/rs/zerolog"
	"github.com/samber/oops"
	oopszerolog "github.com/samber/oops/loggers/zerolog"

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
	Listen        string      `help:"Address to listen on." default:":9443"`
	StateDir      string      `help:"PKI state directory." default:"./state"`
	FuseMountBase string      `help:"Base directory for per-session FUSE mounts." default:"/tmp/cli-box-fuse"`
	Sandbox       bool        `help:"Enable bwrap sandbox." default:"true"`
	SecureDir     string      `help:"Base directory for per-CLI credential stores." default:"./secure"`
	ConfigPath    string      `name:"config" help:"Path to TOML config file. Uses built-in defaults if not set."`
	MountPolicy   MountPolicy `help:"Sandbox mount policy: local or identity." default:"local" enum:"local,identity"`
}

type SessionConfig struct {
	FuseMountBase  string
	SandboxEnabled bool
	SecureDir      string
	MountPolicy    MountPolicy
	Config         *config.Config
	PairingState   *PairingState
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
	zerolog.ErrorStackMarshaler = oopszerolog.OopsStackMarshaller
	zerolog.ErrorMarshalFunc = oopszerolog.OopsMarshalFunc
	level := zerolog.InfoLevel
	if os.Getenv("CLI_BOX_DEBUG") != "" {
		level = zerolog.DebugLevel
	}
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger().Level(level)

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
		return oops.In("config").Wrapf(err, "load config")
	}

	var tlsCfg *tls.Config
	var pairingState *PairingState

	if cmd.StateDir != "" {
		clientCACert, clientCAKey, serverCert, serverKey, err := pki.LoadState(cmd.StateDir)
		if err != nil {
			return oops.In("transport").Wrapf(err, "load PKI state")
		}
		tlsCfg, err = transport.LoadServerTLSDualMode(serverCert, serverKey, clientCACert)
		if err != nil {
			return oops.In("transport").Wrapf(err, "TLS setup")
		}
		pairingState = &PairingState{
			ClientCACert: clientCACert,
			ClientCAKey:  clientCAKey,
			StateDir:     cmd.StateDir,
			Limiter:      NewPairingRateLimiter(),
		}
	}

	var ln net.Listener
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", cmd.Listen, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", cmd.Listen)
	}
	if err != nil {
		return oops.In("transport").Wrapf(err, "listen")
	}
	defer ln.Close()

	if err := os.MkdirAll(cmd.FuseMountBase, 0o700); err != nil {
		return oops.In("exec").Wrapf(err, "fuse mount base setup")
	}

	sessionCfg := SessionConfig{
		FuseMountBase:  cmd.FuseMountBase,
		SandboxEnabled: cmd.Sandbox,
		SecureDir:      cmd.SecureDir,
		MountPolicy:    cmd.MountPolicy,
		Config:         cfg,
		PairingState:   pairingState,
	}

	logger.Info().Stringer("addr", ln.Addr()).Msg("listening")

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		logger.Info().Msg("shutting down")
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
			logger.Error().Err(err).Msg("accept failed")
			continue
		}

		wg.Go(func() {
			handleConnection(ctx, conn, sessionCfg, logger)
		})
	}
}

// handleConnection manages the full lifecycle of a single client connection:
// yamux → FUSE mount → register services → serve → teardown.
// If pairingState is set and the client has no certificate, it gets a pairing-only session.
func handleConnection(ctx context.Context, conn net.Conn, cfg SessionConfig, logger zerolog.Logger) {
	defer conn.Close()
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	remoteAddr := conn.RemoteAddr().String()
	logger.Info().Str("remote", remoteAddr).Msg("connection accepted")

	// Branch on client cert presence for dual-mode TLS
	if cfg.PairingState != nil {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.HandshakeContext(connCtx); err != nil {
				logger.Error().Err(err).Str("remote", remoteAddr).Msg("TLS handshake failed")
				return
			}
			if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
				logger.Info().Str("remote", remoteAddr).Msg("unauthenticated connection, entering pairing mode")
				session, err := yamux.Server(conn, nil)
				if err != nil {
					logger.Error().Err(err).Str("remote", remoteAddr).Msg("yamux setup failed (pairing)")
					return
				}
				handlePairingSession(connCtx, session, cfg.PairingState, logger)
				return
			}
		}
	}

	session, err := yamux.Server(conn, nil)
	if err != nil {
		logger.Error().Err(err).Str("remote", remoteAddr).Msg("yamux setup failed")
		return
	}
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		logger.Error().Err(err).Str("remote", remoteAddr).Msg("peer setup failed")
		return
	}
	defer peer.Close()

	mountpoint, err := os.MkdirTemp(cfg.FuseMountBase, "session-")
	if err != nil {
		logger.Error().Err(err).Str("base", cfg.FuseMountBase).Msg("fuse mount directory setup failed")
		return
	}
	defer os.Remove(mountpoint)

	// Register Command service before serving so it's available immediately.
	// Exec handlers block on fuseReady until the FUSE mount is up.
	fuseReady := make(chan struct{})
	cmdServer := &CommandServer{
		ctx:            connCtx,
		logger:         logger,
		fuseMountpoint: mountpoint,
		sandboxEnabled: cfg.SandboxEnabled,
		secureDir:      cfg.SecureDir,
		mountPolicy:    cfg.MountPolicy,
		config:         cfg.Config,
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
		logger.Error().Err(err).Str("mountpoint", mountpoint).Msg("FUSE mount failed")
		return
	}
	defer func() {
		if err := UnmountFUSE(fuseServer); err != nil {
			logger.Warn().Err(err).Msg("FUSE unmount failed")
		}
	}()

	logger.Info().Str("mountpoint", mountpoint).Str("remote", remoteAddr).Msg("FUSE mounted")
	close(fuseReady)

	// Block until session closes or server shuts down
	select {
	case <-serveDone:
	case <-connCtx.Done():
		logger.Info().Str("remote", remoteAddr).Msg("shutting down connection")
	}

	logger.Info().Str("remote", remoteAddr).Msg("connection closed")
}
