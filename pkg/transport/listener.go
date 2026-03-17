package transport

import (
	"net"

	"github.com/hashicorp/yamux"
)

// yamuxListener adapts a yamux session's Accept into a net.Listener,
// allowing a gRPC server to accept connections from multiplexed streams.
type yamuxListener struct {
	session *yamux.Session
}

func newYamuxListener(session *yamux.Session) net.Listener {
	return &yamuxListener{session: session}
}

func (l *yamuxListener) Accept() (net.Conn, error) {
	return l.session.Accept()
}

func (l *yamuxListener) Close() error {
	return l.session.Close()
}

func (l *yamuxListener) Addr() net.Addr {
	return l.session.Addr()
}
