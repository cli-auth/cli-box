package main

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/yamux"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/cli-auth/cli-box/proto"
)

func setupExecTest(t *testing.T) pb.CommandClient {
	t.Helper()

	serverConn, clientConn := net.Pipe()

	serverSession, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatal(err)
	}

	ready := make(chan struct{})
	close(ready)
	srv := grpc.NewServer()
	pb.RegisterCommandServer(srv, &CommandServer{ctx: context.Background(), logger: zerolog.Nop(), fuseReady: ready})
	go srv.Serve(&testLis{serverSession})

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

	return pb.NewCommandClient(cc)
}

type testLis struct{ s *yamux.Session }

func (l *testLis) Accept() (net.Conn, error) { return l.s.Accept() }
func (l *testLis) Close() error              { return l.s.Close() }
func (l *testLis) Addr() net.Addr            { return l.s.Addr() }

func TestExecEcho(t *testing.T) {
	client := setupExecTest(t)

	stream, err := client.Exec(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	err = stream.Send(&pb.ExecInput{
		Input: &pb.ExecInput_Start{Start: &pb.ExecStart{
			Args: []string{"/bin/echo", "hello world"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var stdout []byte
	var exitCode int32
	gotExit := false

	for !gotExit {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch v := msg.Output.(type) {
		case *pb.ExecOutput_Ready:
		case *pb.ExecOutput_Stdout:
			stdout = append(stdout, v.Stdout...)
		case *pb.ExecOutput_Exit:
			exitCode = v.Exit.ExitCode
			gotExit = true
		}
	}

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if string(stdout) != "hello world\n" {
		t.Fatalf("expected 'hello world\\n', got %q", string(stdout))
	}
}

func TestBuildEnvPrefersClientHomeAndServerUser(t *testing.T) {
	t.Setenv("HOME", "/server/home")
	t.Setenv("USER", "server-user")
	t.Setenv("PATH", "/server/bin")
	t.Setenv("SHELL", "/bin/sh")

	env := buildEnv(
		map[string]string{"HOME": "/global/home", "USER": "global-user"},
		map[string]string{"HOME": "/cli/home", "USER": "cli-user"},
		map[string]string{"HOME": "/client/home", "USER": "client-user", "PATH": "/client/bin"},
	)

	merged := make(map[string]string)
	for _, entry := range env {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		merged[k] = v
	}

	if got := merged["HOME"]; got != "/client/home" {
		t.Fatalf("expected client HOME, got %q", got)
	}
	if got := merged["USER"]; got != "server-user" {
		t.Fatalf("expected server USER, got %q", got)
	}
	if got := merged["PATH"]; got != "/server/bin" {
		t.Fatalf("expected server PATH, got %q", got)
	}
	if got := merged["SHELL"]; got != "/bin/sh" {
		t.Fatalf("expected server SHELL, got %q", got)
	}
}

func TestExecUsesClientHomeAndServerUser(t *testing.T) {
	if _, err := os.Stat("/usr/bin/env"); err != nil {
		t.Skip("/usr/bin/env not available")
	}
	t.Setenv("USER", "server-user")
	t.Setenv("PATH", "/server/bin")

	client := setupExecTest(t)

	stream, err := client.Exec(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	err = stream.Send(&pb.ExecInput{
		Input: &pb.ExecInput_Start{Start: &pb.ExecStart{
			Args: []string{"/usr/bin/env"},
			Env: map[string]string{
				"HOME": "/Users/foo",
				"USER": "client-user",
				"PATH": "/client/bin",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var stdout []byte
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch v := msg.Output.(type) {
		case *pb.ExecOutput_Ready:
		case *pb.ExecOutput_Stdout:
			stdout = append(stdout, v.Stdout...)
		case *pb.ExecOutput_Exit:
			output := string(stdout)
			if !strings.Contains(output, "HOME=/Users/foo\n") {
				t.Fatalf("expected client HOME in env, got %q", output)
			}
			if !strings.Contains(output, "USER=server-user\n") {
				t.Fatalf("expected server USER in env, got %q", output)
			}
			if strings.Contains(output, "PATH=/client/bin\n") {
				t.Fatalf("expected server PATH to win, got %q", output)
			}
			return
		}
	}
}

func TestExecExitCode(t *testing.T) {
	client := setupExecTest(t)

	stream, err := client.Exec(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	err = stream.Send(&pb.ExecInput{
		Input: &pb.ExecInput_Start{Start: &pb.ExecStart{
			Args: []string{"/bin/sh", "-c", "exit 42"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var exitCode int32
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch v := msg.Output.(type) {
		case *pb.ExecOutput_Ready:
		case *pb.ExecOutput_Exit:
			exitCode = v.Exit.ExitCode
			goto gotExit
		}
	}
gotExit:

	if exitCode != 42 {
		t.Fatalf("expected exit code 42, got %d", exitCode)
	}
}

type fakeExecStream struct {
	ctx context.Context
}

func (f *fakeExecStream) Context() context.Context     { return f.ctx }
func (f *fakeExecStream) Send(*pb.ExecOutput) error    { return nil }
func (f *fakeExecStream) Recv() (*pb.ExecInput, error) { return nil, context.Canceled }
func (f *fakeExecStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeExecStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeExecStream) SetTrailer(metadata.MD)       {}
func (f *fakeExecStream) SendMsg(any) error            { return nil }
func (f *fakeExecStream) RecvMsg(any) error            { return context.Canceled }

func TestExecReturnsWhenConnectionContextIsCanceledBeforeFUSEReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv := &CommandServer{
		ctx:       ctx,
		logger:    zerolog.Nop(),
		fuseReady: make(chan struct{}),
	}

	err := srv.Exec(&fakeExecStream{ctx: context.Background()})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestExecStdin(t *testing.T) {
	client := setupExecTest(t)

	stream, err := client.Exec(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	err = stream.Send(&pb.ExecInput{
		Input: &pb.ExecInput_Start{Start: &pb.ExecStart{
			Args: []string{"/bin/cat"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = stream.Send(&pb.ExecInput{
		Input: &pb.ExecInput_Stdin{Stdin: []byte("piped input")},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Close stdin by sending EOF via CloseSend
	stream.CloseSend()

	var stdout []byte
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch v := msg.Output.(type) {
		case *pb.ExecOutput_Ready:
		case *pb.ExecOutput_Stdout:
			stdout = append(stdout, v.Stdout...)
		case *pb.ExecOutput_Exit:
			if string(stdout) != "piped input" {
				t.Fatalf("expected 'piped input', got %q", string(stdout))
			}
			if v.Exit.ExitCode != 0 {
				t.Fatalf("expected exit 0, got %d", v.Exit.ExitCode)
			}
			return
		}
	}
}

func TestExecStderr(t *testing.T) {
	client := setupExecTest(t)

	stream, err := client.Exec(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	err = stream.Send(&pb.ExecInput{
		Input: &pb.ExecInput_Start{Start: &pb.ExecStart{
			Args: []string{"/bin/sh", "-c", "echo error >&2"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var stderr []byte
	for {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		switch v := msg.Output.(type) {
		case *pb.ExecOutput_Ready:
		case *pb.ExecOutput_Stderr:
			stderr = append(stderr, v.Stderr...)
		case *pb.ExecOutput_Exit:
			if string(stderr) != "error\n" {
				t.Fatalf("expected 'error\\n', got %q", string(stderr))
			}
			return
		}
	}
}
