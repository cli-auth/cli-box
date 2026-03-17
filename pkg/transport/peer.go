package transport

import (
	"context"
	"net"

	"github.com/hashicorp/yamux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Peer represents one side of a bidirectional gRPC-over-yamux connection.
// Both sides can simultaneously serve gRPC (via GRPCServer, accepting on
// incoming yamux streams) and call the remote (via ClientConn, opening
// outgoing yamux streams).
type Peer struct {
	GRPCServer *grpc.Server
	ClientConn *grpc.ClientConn
	Session    *yamux.Session
}

// NewPeer creates a Peer from a yamux session. Register services on
// GRPCServer before calling Serve. Use ClientConn to call the remote's
// services. TLS is handled at the TCP layer, so gRPC uses insecure credentials.
func NewPeer(session *yamux.Session) (*Peer, error) {
	cc, err := grpc.NewClient(
		"passthrough:///yamux",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return session.Open()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	return &Peer{
		GRPCServer: grpc.NewServer(),
		ClientConn: cc,
		Session:    session,
	}, nil
}

// Serve starts accepting incoming yamux streams and dispatching them
// to the gRPC server. Blocks until the session is closed.
func (p *Peer) Serve() error {
	return p.GRPCServer.Serve(newYamuxListener(p.Session))
}

// Close shuts down the gRPC server and client connection.
func (p *Peer) Close() {
	p.GRPCServer.GracefulStop()
	p.ClientConn.Close()
}
