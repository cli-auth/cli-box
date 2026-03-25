package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// fakeAddr implements net.Addr for testing.
type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "127.0.0.1:0" }

// fakeTLSConn wraps a net.Conn and reports a fixed NegotiatedProtocol.
type fakeTLSConn struct {
	net.Conn
	proto string
}

func (c *fakeTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: c.proto}
}

func TestConnListenerDeliverAndAccept(t *testing.T) {
	l := newConnListener(fakeAddr{})
	c1, c2 := net.Pipe()
	defer c2.Close()

	l.deliver(c1)

	got, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != c1 {
		t.Fatal("Accept returned wrong connection")
	}
}

func TestConnListenerCloseUnblocksAccept(t *testing.T) {
	l := newConnListener(fakeAddr{})

	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()

	l.Close()

	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
}

func TestConnListenerDeliverAfterCloseDropsConn(t *testing.T) {
	l := newConnListener(fakeAddr{})
	l.Close()

	c1, c2 := net.Pipe()
	defer c2.Close()

	l.deliver(c1) // should close c1 immediately

	// c1 should be closed; reading from c2 should return an error
	c1.SetDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("expected error reading from c2 after c1 closed, got nil")
	}
}

func TestConnListenerAddr(t *testing.T) {
	addr := fakeAddr{}
	l := newConnListener(addr)
	if l.Addr() != addr {
		t.Fatal("Addr() returned unexpected value")
	}
}
