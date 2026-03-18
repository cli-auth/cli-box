package main

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"sync"

	"github.com/hashicorp/yamux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cli-auth/cli-box/pkg/pki"
	"github.com/cli-auth/cli-box/pkg/transport"
	pb "github.com/cli-auth/cli-box/proto"
)

type PairingState struct {
	CACert   []byte
	CAKey    []byte
	StateDir string
}

type PairingServer struct {
	pb.UnimplementedPairingServer
	state  *PairingState
	logger *slog.Logger
	mu     sync.Mutex
}

func (s *PairingServer) Pair(ctx context.Context, req *pb.PairRequest) (*pb.PairResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Token == "" {
		return nil, status.Error(codes.Unauthenticated, "token required")
	}
	if len(req.Csr) == 0 {
		return nil, status.Error(codes.InvalidArgument, "CSR required")
	}

	storedToken, err := pki.LoadToken(s.state.StateDir)
	if err != nil {
		s.logger.Warn("no pairing token available")
		return nil, status.Error(codes.Unauthenticated, "no pairing token available")
	}

	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(storedToken)) != 1 {
		s.logger.Warn("invalid pairing token")
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	clientCert, err := pki.SignCSR(s.state.CACert, s.state.CAKey, req.Csr)
	if err != nil {
		s.logger.Error("sign CSR failed", "error", err)
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}

	if err := pki.ConsumeToken(s.state.StateDir); err != nil {
		s.logger.Error("consume token failed", "error", err)
	}

	s.logger.Info("client paired successfully")

	return &pb.PairResponse{
		ClientCert: clientCert,
		CaCert:     s.state.CACert,
	}, nil
}

// handlePairingSession serves only the Pairing gRPC service on a yamux session
// (no FUSE, no Command). Used for unauthenticated connections.
func handlePairingSession(ctx context.Context, session *yamux.Session, state *PairingState, logger *slog.Logger) {
	defer session.Close()

	peer, err := transport.NewPeer(session)
	if err != nil {
		logger.Error("peer setup failed (pairing)", "error", err)
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
