package transport

import (
	"context"
	"net"
	"testing"

	"github.com/hashicorp/yamux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cli-auth/cli-box/proto"
)

// stubCommandServer is a minimal Command service for testing.
type stubCommandServer struct {
	pb.UnimplementedCommandServer
}

// stubFSServer is a minimal FileSystem service for testing.
type stubFSServer struct {
	pb.UnimplementedFileSystemServer
}

func (s *stubFSServer) GetAttr(_ context.Context, req *pb.GetAttrRequest) (*pb.GetAttrResponse, error) {
	if req.Path == "/test" {
		return &pb.GetAttrResponse{Attr: &pb.FileAttr{Size: 42, Mode: 0o100644}}, nil
	}
	return &pb.GetAttrResponse{Errno: 2}, nil
}

func TestBidirectionalGRPC(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	clientSession, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatal(err)
	}

	serverSession, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set up peers — each side is both gRPC server and client
	clientPeer, err := NewPeer(clientSession)
	if err != nil {
		t.Fatal(err)
	}

	serverPeer, err := NewPeer(serverSession)
	if err != nil {
		t.Fatal(err)
	}

	// Client side serves FileSystem (local serves FS to remote)
	pb.RegisterFileSystemServer(clientPeer.GRPCServer, &stubFSServer{})

	// Server side serves Command (remote serves Command to local)
	pb.RegisterCommandServer(serverPeer.GRPCServer, &stubCommandServer{})

	go clientPeer.Serve()
	go serverPeer.Serve()

	defer clientPeer.Close()
	defer serverPeer.Close()

	// Remote calls local's FileSystem
	fsClient := pb.NewFileSystemClient(serverPeer.ClientConn)
	resp, err := fsClient.GetAttr(t.Context(), &pb.GetAttrRequest{Path: "/test"})
	if err != nil {
		t.Fatalf("GetAttr failed: %v", err)
	}
	if resp.Attr.Size != 42 {
		t.Fatalf("expected size 42, got %d", resp.Attr.Size)
	}
	if resp.Attr.Mode != 0o100644 {
		t.Fatalf("expected mode 0100644, got %o", resp.Attr.Mode)
	}

	// Verify ENOENT path
	resp, err = fsClient.GetAttr(t.Context(), &pb.GetAttrRequest{Path: "/nonexistent"})
	if err != nil {
		t.Fatalf("GetAttr for nonexistent failed: %v", err)
	}
	if resp.Errno != 2 {
		t.Fatalf("expected errno 2 (ENOENT), got %d", resp.Errno)
	}

	// Local calls remote's Command — Exec is streaming, so just verify
	// the connection works by calling it and expecting the stream to open
	cmdClient := pb.NewCommandClient(clientPeer.ClientConn)
	stream, err := cmdClient.Exec(t.Context())
	if err != nil {
		t.Fatalf("Exec stream open failed: %v", err)
	}

	// The stub server returns Unimplemented, which terminates the stream.
	// Depending on timing, Recv sees either Unimplemented status or EOF.
	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected error from unimplemented Exec, got nil")
	}
	st, ok := status.FromError(err)
	if ok && st.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", err)
	}
}

func TestNewPeerFromPipe(t *testing.T) {
	c, s := net.Pipe()

	cs, err := yamux.Client(c, nil)
	if err != nil {
		t.Fatal(err)
	}

	ss, err := yamux.Server(s, nil)
	if err != nil {
		t.Fatal(err)
	}

	cp, err := NewPeer(cs)
	if err != nil {
		t.Fatal(err)
	}

	sp, err := NewPeer(ss)
	if err != nil {
		t.Fatal(err)
	}

	if cp.GRPCServer == nil || cp.ClientConn == nil || cp.Session == nil {
		t.Fatal("client peer has nil fields")
	}

	if sp.GRPCServer == nil || sp.ClientConn == nil || sp.Session == nil {
		t.Fatal("server peer has nil fields")
	}

	cp.Close()
	sp.Close()
}
