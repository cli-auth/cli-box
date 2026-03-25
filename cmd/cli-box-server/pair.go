package main

import (
	"context"
	"crypto/subtle"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cli-auth/cli-box/pkg/admin"
	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

type PairingState struct {
	ClientCACert []byte
	ClientCAKey  []byte
	StateDir     string
	Limiter      *PairingRateLimiter
	Events       *admin.EventStore
}

type PairingServer struct {
	pb.UnimplementedPairingServer
	state  *PairingState
	logger zerolog.Logger
	mu     sync.Mutex
}

const (
	pairingAttemptWindow = time.Minute
	pairingMaxAttempts   = 20
)

type PairingRateLimiter struct {
	mu       sync.Mutex
	attempts []time.Time
}

func NewPairingRateLimiter() *PairingRateLimiter {
	return &PairingRateLimiter{}
}

func (l *PairingRateLimiter) Allow(at time.Time) bool {
	if l == nil {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.attempts = pruneAttempts(l.attempts, at)
	return len(l.attempts) < pairingMaxAttempts
}

func (l *PairingRateLimiter) RecordFailure(at time.Time) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.attempts = append(pruneAttempts(l.attempts, at), at)
}

func pruneAttempts(attempts []time.Time, at time.Time) []time.Time {
	keepFrom := 0
	cutoff := at.Add(-pairingAttemptWindow)
	for keepFrom < len(attempts) && attempts[keepFrom].Before(cutoff) {
		keepFrom++
	}
	if keepFrom == len(attempts) {
		return attempts[:0]
	}
	return attempts[keepFrom:]
}

func (s *PairingServer) Pair(ctx context.Context, req *pb.PairRequest) (*pb.PairResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if !s.state.Limiter.Allow(now) {
		s.logger.Warn().Msg("pairing rate limit exceeded")
		s.state.Events.Add("pairing.rate_limited", "warn", "pairing rate limit exceeded", nil)
		return nil, status.Error(codes.ResourceExhausted, "too many attempts, retry later")
	}

	if req.Token == "" {
		s.state.Events.Add("pairing.missing_token", "warn", "pairing rejected: token required", nil)
		return nil, status.Error(codes.Unauthenticated, "token required")
	}
	if len(req.Csr) == 0 {
		s.state.Events.Add("pairing.missing_csr", "warn", "pairing rejected: CSR required", nil)
		return nil, status.Error(codes.InvalidArgument, "CSR required")
	}

	storedToken, err := pki.LoadToken(s.state.StateDir)
	if err != nil {
		s.logger.Warn().Msg("no pairing token available")
		s.state.Events.Add("pairing.unavailable", "warn", "pairing rejected: no token available", nil)
		return nil, status.Error(codes.Unauthenticated, "no pairing token available")
	}
	if storedToken.Expired(time.Now()) {
		if err := pki.ConsumeToken(s.state.StateDir); err != nil && !os.IsNotExist(err) {
			s.logger.Error().Err(err).Msg("consume expired token failed")
		}
		s.logger.Warn().Msg("expired pairing token")
		s.state.Events.Add("pairing.expired_token", "warn", "pairing rejected: token expired", nil)
		return nil, status.Error(codes.Unauthenticated, "expired token")
	}

	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(storedToken.Value)) != 1 {
		s.state.Limiter.RecordFailure(now)
		s.logger.Warn().Msg("invalid pairing token")
		s.state.Events.Add("pairing.invalid_token", "warn", "pairing rejected: invalid token", nil)
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	clientCert, err := pki.SignCSR(s.state.ClientCACert, s.state.ClientCAKey, req.Csr)
	if err != nil {
		s.logger.Error().Err(err).Msg("sign CSR failed")
		s.state.Events.Add("pairing.invalid_csr", "warn", "pairing rejected: invalid CSR", nil)
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}

	if err := pki.ConsumeToken(s.state.StateDir); err != nil {
		s.logger.Error().Err(err).Msg("consume token failed")
	}

	s.logger.Info().Msg("client paired successfully")
	s.state.Events.Add("pairing.success", "info", "client paired successfully", nil)

	return &pb.PairResponse{
		ClientCert: clientCert,
		CaCert:     s.state.ClientCACert,
	}, nil
}

// handlePairingSession serves only the Pairing gRPC service on a yamux session
// (no FUSE, no Command). Used for unauthenticated connections.
func handlePairingSession(ctx context.Context, session *yamux.Session, state *PairingState, logger zerolog.Logger) {
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		logger.Error().Err(err).Msg("peer setup failed (pairing)")
		return
	}
	defer peer.Close()

	pb.RegisterPairingServer(peer.GRPCServer, &PairingServer{
		state:  state,
		logger: logger,
	})

	serveDone := make(chan struct{})
	go func() {
		peer.Serve()
		close(serveDone)
	}()

	select {
	case <-serveDone:
	case <-ctx.Done():
	}
}
