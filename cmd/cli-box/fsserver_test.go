package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hashicorp/yamux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/cli-auth/cli-box/proto"
)

func setupFSTest(t *testing.T) (pb.FileSystemClient, string) {
	t.Helper()
	tmpDir := t.TempDir()

	serverConn, clientConn := net.Pipe()

	serverSession, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := grpc.NewServer()
	pb.RegisterFileSystemServer(srv, NewFSServer(tmpDir))
	go srv.Serve(&yamuxLis{serverSession})

	clientSession, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatal(err)
	}

	cc, err := grpc.NewClient(
		"passthrough:///yamux",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return clientSession.Open()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		cc.Close()
		srv.GracefulStop()
	})

	return pb.NewFileSystemClient(cc), tmpDir
}

// yamuxLis adapts yamux.Session to net.Listener for test setup.
type yamuxLis struct{ s *yamux.Session }

func (l *yamuxLis) Accept() (net.Conn, error) { return l.s.Accept() }
func (l *yamuxLis) Close() error              { return l.s.Close() }
func (l *yamuxLis) Addr() net.Addr            { return l.s.Addr() }

func TestGetAttr(t *testing.T) {
	client, dir := setupFSTest(t)
	os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello"), 0o644)

	resp, err := client.GetAttr(context.Background(), &pb.GetAttrRequest{Path: "/hello.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Errno != 0 {
		t.Fatalf("errno %d", resp.Errno)
	}
	if resp.Attr.Size != 5 {
		t.Fatalf("expected size 5, got %d", resp.Attr.Size)
	}
}

func TestGetAttrNotFound(t *testing.T) {
	client, _ := setupFSTest(t)

	resp, err := client.GetAttr(context.Background(), &pb.GetAttrRequest{Path: "/nope"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Errno != int32(syscall.ENOENT) {
		t.Fatalf("expected ENOENT, got %d", resp.Errno)
	}
}

func TestCreateReadWrite(t *testing.T) {
	client, dir := setupFSTest(t)

	cr, err := client.Create(context.Background(), &pb.CreateRequest{
		Path:  "/test.txt",
		Mode:  0o644,
		Flags: uint32(os.O_RDWR | os.O_CREATE),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cr.Errno != 0 {
		t.Fatalf("create errno %d", cr.Errno)
	}

	wr, err := client.Write(context.Background(), &pb.WriteRequest{
		Fh:     cr.Fh,
		Offset: 0,
		Data:   []byte("hello world"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if wr.Written != 11 {
		t.Fatalf("expected 11 bytes written, got %d", wr.Written)
	}

	rr, err := client.Read(context.Background(), &pb.ReadRequest{
		Fh:     cr.Fh,
		Offset: 0,
		Size:   64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(rr.Data) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", string(rr.Data))
	}

	_, err = client.Release(context.Background(), &pb.ReleaseRequest{Fh: cr.Fh})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the file on disk
	data, err := os.ReadFile(filepath.Join(dir, "test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Fatalf("on disk: %q", string(data))
	}
}

func TestMkdirReadDirRmdir(t *testing.T) {
	client, _ := setupFSTest(t)

	mr, err := client.Mkdir(context.Background(), &pb.MkdirRequest{Path: "/subdir", Mode: 0o755})
	if err != nil {
		t.Fatal(err)
	}
	if mr.Errno != 0 {
		t.Fatalf("mkdir errno %d", mr.Errno)
	}

	// Create a file inside
	cr, err := client.Create(context.Background(), &pb.CreateRequest{
		Path:  "/subdir/file.txt",
		Mode:  0o644,
		Flags: uint32(os.O_RDWR | os.O_CREATE),
	})
	if err != nil {
		t.Fatal(err)
	}
	client.Release(context.Background(), &pb.ReleaseRequest{Fh: cr.Fh})

	odr, err := client.OpenDir(context.Background(), &pb.OpenDirRequest{Path: "/subdir"})
	if err != nil {
		t.Fatal(err)
	}

	rdr, err := client.ReadDir(context.Background(), &pb.ReadDirRequest{Path: "/subdir", Fh: odr.Fh})
	if err != nil {
		t.Fatal(err)
	}
	if len(rdr.Entries) != 1 || rdr.Entries[0].Name != "file.txt" {
		t.Fatalf("expected [file.txt], got %v", rdr.Entries)
	}

	client.ReleaseDir(context.Background(), &pb.ReleaseDirRequest{Fh: odr.Fh})

	// Clean up and rmdir
	client.Unlink(context.Background(), &pb.UnlinkRequest{Path: "/subdir/file.txt"})
	rmr, err := client.Rmdir(context.Background(), &pb.RmdirRequest{Path: "/subdir"})
	if err != nil {
		t.Fatal(err)
	}
	if rmr.Errno != 0 {
		t.Fatalf("rmdir errno %d", rmr.Errno)
	}
}

func TestSymlinkAndReadLink(t *testing.T) {
	client, dir := setupFSTest(t)
	os.WriteFile(filepath.Join(dir, "target.txt"), []byte("data"), 0o644)

	sr, err := client.Symlink(context.Background(), &pb.SymlinkRequest{
		Target:   "target.txt",
		LinkPath: "/link.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sr.Errno != 0 {
		t.Fatalf("symlink errno %d", sr.Errno)
	}

	rl, err := client.ReadLink(context.Background(), &pb.ReadLinkRequest{Path: "/link.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if rl.Target != "target.txt" {
		t.Fatalf("expected target 'target.txt', got %q", rl.Target)
	}
}

func TestRename(t *testing.T) {
	client, dir := setupFSTest(t)
	os.WriteFile(filepath.Join(dir, "old.txt"), []byte("data"), 0o644)

	rr, err := client.Rename(context.Background(), &pb.RenameRequest{
		OldPath: "/old.txt",
		NewPath: "/new.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rr.Errno != 0 {
		t.Fatalf("rename errno %d", rr.Errno)
	}

	if _, err := os.Stat(filepath.Join(dir, "new.txt")); err != nil {
		t.Fatal("new.txt should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "old.txt")); !os.IsNotExist(err) {
		t.Fatal("old.txt should not exist")
	}
}

func TestStatFs(t *testing.T) {
	client, _ := setupFSTest(t)

	resp, err := client.StatFs(context.Background(), &pb.StatFsRequest{Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Errno != 0 {
		t.Fatalf("statfs errno %d", resp.Errno)
	}
	if resp.Bsize == 0 {
		t.Fatal("expected non-zero bsize")
	}
}
