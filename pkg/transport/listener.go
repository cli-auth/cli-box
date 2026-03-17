package transport

import (
	"net"
	"sync"

	"github.com/hashicorp/yamux"
)

// yamuxListener adapts a yamux session's Accept into a net.Listener,
// allowing a gRPC server to accept connections from multiplexed streams.
//
// Close does NOT close the yamux session — it only unblocks Accept so
// GracefulStop can drain in-flight RPCs while the session stays alive.
// The caller is responsible for closing the session afterwards.
type yamuxListener struct {
	session *yamux.Session
	done    chan struct{}
	once    sync.Once
}

func newYamuxListener(session *yamux.Session) net.Listener {
	return &yamuxListener{session: session, done: make(chan struct{})}
}

func (l *yamuxListener) Accept() (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, e := l.session.Accept()
		ch <- result{c, e}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *yamuxListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *yamuxListener) Addr() net.Addr {
	return l.session.Addr()
}
