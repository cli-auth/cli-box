package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/hashicorp/yamux"
	"github.com/rs/zerolog"
	"github.com/samber/oops"
	oopszerolog "github.com/samber/oops/loggers/zerolog"

	"github.com/cli-auth/cli-box/pkg/admin"
	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/policy"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

// version is set at build time via -ldflags "-X main.version=v1.2.3".
var version = "dev"

type CLI struct {
	Serve     ServeCmd     `cmd:"" help:"Run the cli-box server."`
	Init      InitCmd      `cmd:"" help:"Initialize PKI state."`
	AddClient AddClientCmd `cmd:"" name:"add-client" help:"Mint a one-time pairing token."`
	Policy    PolicyCmd    `cmd:"" help:"Manage policy scripts."`
	Version   VersionCmd   `cmd:"" help:"Print version."`
}

type VersionCmd struct{}

func (cmd *VersionCmd) Run() error {
	fmt.Printf("cli-box-server %s\n", version)
	return nil
}

type ServeCmd struct {
	Listen        string      `help:"Address to listen on." default:":9443"`
	StateDir      string      `help:"PKI state directory." default:"./state"`
	FuseMountBase string      `help:"Base directory for per-session FUSE mounts." default:"/tmp/cli-box-fuse"`
	Sandbox       bool        `help:"Enable bwrap sandbox." default:"true"`
	SecureDir     string      `help:"Base directory for per-CLI credential stores." default:"./secure"`
	PolicyDir     string      `help:"Directory containing policy scripts." default:"./policies"`
	MountPolicy   MountPolicy `help:"Sandbox mount policy: local or identity." default:"local" enum:"local,identity"`
	AdminCert     string      `help:"Admin HTTPS certificate file (PEM). If omitted, a self-signed cert is generated."`
	AdminKey      string      `help:"Admin HTTPS private key file (PEM). Required when --admin-cert is set."`
}

type SessionConfig struct {
	FuseMountBase  string
	SandboxEnabled bool
	SecureDir      string
	MountPolicy    MountPolicy
	PolicyEngine   *policy.Engine
	PairingState   *PairingState
	Events         *admin.EventStore
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

func runServe(cmd ServeCmd) error {
	if (cmd.AdminCert == "") != (cmd.AdminKey == "") {
		return oops.Errorf("--admin-cert and --admin-key must both be set or both omitted")
	}

	zerolog.ErrorStackMarshaler = oopszerolog.OopsStackMarshaller
	zerolog.ErrorMarshalFunc = oopszerolog.OopsMarshalFunc
	level := zerolog.InfoLevel
	if os.Getenv("CLI_BOX_DEBUG") != "" {
		level = zerolog.DebugLevel
	}
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger().Level(level)

	if _, err := os.Stat(filepath.Join(cmd.StateDir, "client_ca.crt")); os.IsNotExist(err) {
		token, err := pki.InitStateDir(cmd.StateDir, nil)
		if err != nil {
			return oops.In("pki").Wrapf(err, "auto-init state dir")
		}
		fp, err := loadServerFingerprint(cmd.StateDir)
		if err != nil {
			return err
		}
		fmt.Println("================================================================")
		fmt.Printf("Pairing token:      %s\n", token)
		fmt.Printf("Token expires in:   %d minutes\n", int(pki.PairingTokenTTL/time.Minute))
		fmt.Printf("Server fingerprint: %s\n", fp)
		fmt.Println("================================================================")
	}

	policyEngine, err := policy.NewEngine(cmd.PolicyDir)
	if err != nil {
		return oops.In("policy").Wrapf(err, "load policy scripts")
	}
	logger.Info().Str("dir", cmd.PolicyDir).Msg("policy engine loaded")

	if err := os.MkdirAll(cmd.FuseMountBase, 0o700); err != nil {
		return oops.In("exec").Wrapf(err, "fuse mount base setup")
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	runtime := NewServerRuntime(ctx, cmd, logger, policyEngine)
	if err := runtime.initEventStore(); err != nil {
		return err
	}
	if err := runtime.initAdminServer(); err != nil {
		return err
	}
	if err := runtime.StartTransportServer(); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		logger.Info().Msg("shutting down")
		runtime.Close()
	}()
	<-ctx.Done()
	return nil
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
	if cfg.Events != nil {
		cfg.Events.Add("transport.connection_opened", "verbose", "transport connection accepted", map[string]string{
			"remote": remoteAddr,
		})
	}

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
		policyEngine:   cfg.PolicyEngine,
		fuseReady:      fuseReady,
		events:         cfg.Events,
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
	if cfg.Events != nil {
		cfg.Events.Add("transport.connection_closed", "verbose", "transport connection closed", map[string]string{
			"remote": remoteAddr,
		})
	}
}
