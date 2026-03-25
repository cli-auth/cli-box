package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/samber/oops"

	"github.com/cli-auth/cli-box/internal/adminui"
	"github.com/cli-auth/cli-box/pkg/admin"
	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/policy"
	"github.com/cli-auth/cli-box/pkg/transport"
)

var errTransportNotConfigured = errors.New("transport not configured")

type ServerRuntime struct {
	ctx    context.Context
	cmd    ServeCmd
	logger zerolog.Logger

	startedAt time.Time
	events    *admin.EventStore
	auth      *admin.AuthStore
	ui        *adminui.App

	policyMu     sync.RWMutex
	policyEngine *policy.Engine

	adminServer *AdminServer

	transportMu       sync.Mutex
	transportListener net.Listener
	pairingState      *PairingState
}

func NewServerRuntime(ctx context.Context, cmd ServeCmd, logger zerolog.Logger, policyEngine *policy.Engine) *ServerRuntime {
	stateDir := cmd.StateDir
	if stateDir == "" {
		stateDir = "."
	}

	return &ServerRuntime{
		ctx:          ctx,
		cmd:          cmd,
		logger:       logger,
		startedAt:    time.Now().UTC(),
		auth:         admin.NewAuthStore(filepath.Join(stateDir, "admin-auth.json")),
		ui:           adminui.Load(),
		policyEngine: policyEngine,
	}
}

func (s *ServerRuntime) initEventStore() error {
	stateDir := s.cmd.StateDir
	if stateDir == "" {
		stateDir = "."
	}
	store, err := admin.NewEventStore(filepath.Join(stateDir, "events.db"))
	if err != nil {
		return err
	}
	s.events = store
	return nil
}

func (s *ServerRuntime) initAdminServer() error {
	server, err := NewAdminServer(s)
	if err != nil {
		return err
	}
	s.adminServer = server
	return nil
}

func (s *ServerRuntime) StartTransportServer() error {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()

	if s.transportListener != nil {
		return nil
	}
	if s.cmd.StateDir == "" {
		return errTransportNotConfigured
	}

	clientCACert, clientCAKey, serverCert, serverKey, err := pki.LoadState(s.cmd.StateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.events.Add("transport.pending", "warn", "transport listener not started: PKI state missing", nil)
			return errTransportNotConfigured
		}
		return oops.In("transport").Wrapf(err, "load PKI state")
	}

	adminCert, err := s.loadAdminCert()
	if err != nil {
		return err
	}

	tlsCfg, err := transport.LoadServerTLSDualMode(serverCert, serverKey, clientCACert, adminCert)
	if err != nil {
		return oops.In("transport").Wrapf(err, "TLS setup")
	}

	ln, err := tls.Listen("tcp", s.cmd.Listen, tlsCfg)
	if err != nil {
		return oops.In("transport").Wrapf(err, "listen")
	}

	s.transportListener = ln
	s.pairingState = &PairingState{
		ClientCACert: clientCACert,
		ClientCAKey:  clientCAKey,
		StateDir:     s.cmd.StateDir,
		Limiter:      NewPairingRateLimiter(),
		Events:       s.events,
	}
	s.events.Add("transport.started", "info", "transport listener started", map[string]string{
		"addr": ln.Addr().String(),
	})
	s.logger.Info().Stringer("addr", ln.Addr()).Msg("transport listening")
	if host, port, err := net.SplitHostPort(ln.Addr().String()); err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "localhost"
		}
		fmt.Println("================================================================")
		fmt.Printf("Admin UI: https://%s\n", net.JoinHostPort(host, port))
		fmt.Println("================================================================")
	}

	adminLn := newConnListener(ln.Addr())
	s.adminServer.Serve(adminLn)
	go s.acceptMerged(ln, adminLn)
	go func() {
		<-s.ctx.Done()
		ln.Close()
		adminLn.Close()
	}()

	return nil
}

func (s *ServerRuntime) loadAdminCert() (tls.Certificate, error) {
	if s.cmd.AdminCert != "" {
		cert, err := tls.LoadX509KeyPair(s.cmd.AdminCert, s.cmd.AdminKey)
		if err != nil {
			return tls.Certificate{}, oops.In("admin").Wrapf(err, "load admin cert")
		}
		return cert, nil
	}
	s.logger.Info().Msg("no --admin-cert set, generating self-signed cert for admin HTTPS")
	return transport.GenerateSelfSignedCert()
}

// connListener is a net.Listener backed by a channel. It lets the merged TLS
// accept loop hand admin connections to http.Server.Serve without opening a
// second TCP port.
type connListener struct {
	addr  net.Addr
	conns chan net.Conn
	once  sync.Once
	done  chan struct{}
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{
		addr:  addr,
		conns: make(chan net.Conn, 32),
		done:  make(chan struct{}),
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }

func (l *connListener) deliver(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.done:
		conn.Close()
	}
}

func (s *ServerRuntime) acceptMerged(ln net.Listener, adminLn *connListener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.logger.Error().Err(err).Msg("accept failed")
			s.events.Add("transport.accept_failed", "error", "transport accept failed", map[string]string{
				"error": err.Error(),
			})
			continue
		}
		go s.routeConn(conn, adminLn)
	}
}

func (s *ServerRuntime) routeConn(conn net.Conn, adminLn *connListener) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		// non-TLS: shouldn't happen on a tls.Listen socket, but default to admin
		adminLn.deliver(conn)
		return
	}
	if err := tlsConn.HandshakeContext(s.ctx); err != nil {
		tlsConn.Close()
		return
	}
	if tlsConn.ConnectionState().NegotiatedProtocol == transport.ProtoCLIBox {
		go handleConnection(s.ctx, tlsConn, s.buildSessionConfig(), s.logger)
		return
	}
	adminLn.deliver(tlsConn)
}

func (s *ServerRuntime) buildSessionConfig() SessionConfig {
	return SessionConfig{
		FuseMountBase:  s.cmd.FuseMountBase,
		SandboxEnabled: s.cmd.Sandbox,
		SecureDir:      s.cmd.SecureDir,
		MountPolicy:    s.cmd.MountPolicy,
		PolicyEngine:   s.PolicyEngine(),
		PairingState:   s.pairingState,
		Events:         s.events,
	}
}

func (s *ServerRuntime) Close() {
	s.transportMu.Lock()
	if s.transportListener != nil {
		_ = s.transportListener.Close()
	}
	s.transportMu.Unlock()

	if s.adminServer != nil {
		_ = s.adminServer.Close(context.Background())
	}

	_ = s.events.Close()
}

func (s *ServerRuntime) PolicyEngine() *policy.Engine {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.policyEngine
}

func (s *ServerRuntime) PolicyCount() int {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	if s.policyEngine == nil {
		return 0
	}
	return s.policyEngine.PolicyCount()
}

func (s *ServerRuntime) ReloadPolicies() error {
	engine, err := policy.NewEngine(s.cmd.PolicyDir)
	if err != nil {
		return err
	}

	s.policyMu.Lock()
	s.policyEngine = engine
	s.policyMu.Unlock()

	s.events.Add("policy.reloaded", "info", "policy engine reloaded", map[string]string{
		"count": strconv.Itoa(engine.PolicyCount()),
	})
	return nil
}

func (s *ServerRuntime) TransportStatus() admin.TransportStatus {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()

	status := admin.TransportStatus{
		Configured: s.cmd.StateDir != "",
		Listen:     s.cmd.Listen,
	}
	if s.transportListener != nil {
		status.Listening = true
		status.Address = s.transportListener.Addr().String()
	}
	if s.pairingState != nil {
		status.Initialized = true
	}
	return status
}

func (s *ServerRuntime) PairingStatus() admin.PairingStatus {
	status := admin.PairingStatus{
		StateDir: s.cmd.StateDir,
	}
	if s.cmd.StateDir == "" {
		return status
	}

	fp, err := loadServerFingerprint(s.cmd.StateDir)
	if err == nil {
		status.Initialized = true
		status.ServerFingerprint = fp
	}

	token, err := pki.LoadToken(s.cmd.StateDir)
	if err == nil {
		status.TokenPresent = true
		status.TokenExpiresAt = token.ExpiresAt.UTC()
		status.Token = token.Value
		return status
	}
	if !errors.Is(err, os.ErrNotExist) {
		status.TokenError = err.Error()
	}
	return status
}

func (s *ServerRuntime) BootstrapAdmin(password string) error {
	if err := s.auth.Bootstrap(password); err != nil {
		return err
	}
	s.events.Add("admin.bootstrap", "info", "admin password bootstrapped", nil)
	return nil
}

func (s *ServerRuntime) ServerConfig() admin.ServerConfigResponse {
	return admin.ServerConfigResponse{
		Listen:        s.cmd.Listen,
		StateDir:      s.cmd.StateDir,
		FuseMountBase: s.cmd.FuseMountBase,
		SecureDir:     s.cmd.SecureDir,
		PolicyDir:     s.cmd.PolicyDir,
		MountPolicy:   string(s.cmd.MountPolicy),
		Sandbox:       s.cmd.Sandbox,
	}
}

func (s *ServerRuntime) ServerStatus() admin.ServerStatusResponse {
	pairing := s.PairingStatus()
	transport := s.TransportStatus()
	return admin.ServerStatusResponse{
		StartedAt:       s.startedAt,
		UptimeSeconds:   int64(time.Since(s.startedAt).Seconds()),
		Transport:       transport,
		Pairing:         pairing,
		PolicyCount:     s.PolicyCount(),
		BootstrapNeeded: !s.auth.IsConfigured(),
	}
}

func requirePolicyFileName(name string) error {
	if filepath.Ext(name) != ".star" {
		return oops.In("policy").Errorf("policy file must end with .star")
	}
	base := strings.TrimSuffix(name, ".star")
	if name != "_init.star" && !validMountName(base) {
		return oops.In("policy").Errorf("invalid policy file %q", name)
	}
	return nil
}

// validPolicyFileOrDisabled accepts both foo.star and foo.star.disabled names.
func validPolicyFileOrDisabled(name string) bool {
	starName := strings.TrimSuffix(name, ".disabled")
	return requirePolicyFileName(starName) == nil
}

func splitHostsCSV(value string) []string {
	var hosts []string
	for _, host := range strings.Split(value, ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}
