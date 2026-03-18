package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"

	"github.com/cli-auth/cli-box/pkg/config"
	pb "github.com/cli-auth/cli-box/proto"
)

type CommandServer struct {
	pb.UnimplementedCommandServer
	ctx            context.Context
	logger         *slog.Logger
	fuseMountpoint string
	sandboxEnabled bool
	secureDir      string
	config         *config.Config
	fuseReady      chan struct{}
}

func (s *CommandServer) Exec(stream pb.Command_ExecServer) error {
	// Wait for FUSE mount before running any commands
	select {
	case <-s.fuseReady:
	case <-s.ctx.Done():
		return s.ctx.Err()
	}

	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	start := msg.GetStart()
	if start == nil {
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}

	args := start.Args
	if len(args) == 0 {
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}

	s.logger.Debug("exec", "args", args, "cwd", start.Cwd, "tty", start.Tty, "sandbox", s.sandboxEnabled)

	cliName := args[0]
	cwd := start.Cwd
	if s.sandboxEnabled && s.config != nil {
		sc := NewSandboxConfig(cliName, s.fuseMountpoint, cwd, s.secureDir, start.Env["HOME"], s.config)
		args = sc.WrapCommand(args)
		cwd = "" // bwrap --chdir handles cwd inside the sandbox
	} else if s.fuseMountpoint != "" {
		cwd = filepath.Join(s.fuseMountpoint, cwd)
	}

	s.logger.Debug("exec resolved", "cwd", cwd, "args", args)

	var globalEnv, cliEnv map[string]string
	if s.config != nil {
		globalEnv = s.config.Env
		if cli, ok := s.config.CLI[cliName]; ok {
			cliEnv = cli.Env
		}
	}

	cmd := exec.CommandContext(s.ctx, args[0], args[1:]...)
	cmd.Dir = cwd
	cmd.Env = buildEnv(globalEnv, cliEnv, start.Env)

	if start.Tty {
		return s.execWithPTY(stream, cmd, start)
	}
	return s.execWithPipes(stream, cmd)
}

func (s *CommandServer) execWithPTY(stream pb.Command_ExecServer, cmd *exec.Cmd, start *pb.ExecStart) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		s.logger.Debug("pty.Start failed", "error", err)
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}
	defer ptmx.Close()
	s.logger.Debug("pty started", "pid", cmd.Process.Pid)

	if err := stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Ready{Ready: &pb.ExecReady{}},
	}); err != nil {
		return err
	}

	if ws := start.WindowSize; ws != nil {
		pty.Setsize(ptmx, &pty.Winsize{
			Rows: uint16(ws.Rows),
			Cols: uint16(ws.Cols),
		})
	}

	// Stream PTY output to client
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				stream.Send(&pb.ExecOutput{
					Output: &pb.ExecOutput_Stdout{Stdout: data},
				})
			}
			if err != nil {
				return
			}
		}
	})

	// Handle incoming messages (stdin, signals, resize)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				ptmx.Close()
				return
			}
			switch v := msg.Input.(type) {
			case *pb.ExecInput_Stdin:
				ptmx.Write(v.Stdin)
			case *pb.ExecInput_Signal:
				if cmd.Process != nil {
					cmd.Process.Signal(syscall.Signal(v.Signal.Signum))
				}
			case *pb.ExecInput_Resize:
				pty.Setsize(ptmx, &pty.Winsize{
					Rows: uint16(v.Resize.Rows),
					Cols: uint16(v.Resize.Cols),
				})
			}
		}
	}()

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		s.logger.Debug("pty cmd.Wait", "error", err)
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	wg.Wait()
	s.logger.Debug("pty done", "exitCode", exitCode)

	return stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: int32(exitCode)}},
	})
}

func (s *CommandServer) execWithPipes(stream pb.Command_ExecServer, cmd *exec.Cmd) error {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}

	if err := cmd.Start(); err != nil {
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}

	if err := stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Ready{Ready: &pb.ExecReady{}},
	}); err != nil {
		return err
	}

	var wg sync.WaitGroup

	// Stream stdout
	wg.Go(func() {
		streamOutput(stream, stdout, false)
	})

	// Stream stderr
	wg.Go(func() {
		streamOutput(stream, stderr, true)
	})

	// Handle incoming messages
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				stdin.Close()
				return
			}
			switch v := msg.Input.(type) {
			case *pb.ExecInput_Stdin:
				stdin.Write(v.Stdin)
			case *pb.ExecInput_Signal:
				if cmd.Process != nil {
					cmd.Process.Signal(syscall.Signal(v.Signal.Signum))
				}
			}
		}
	}()

	wg.Wait()

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: int32(exitCode)}},
	})
}

func streamOutput(stream pb.Command_ExecServer, r io.Reader, isStderr bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			if isStderr {
				stream.Send(&pb.ExecOutput{
					Output: &pb.ExecOutput_Stderr{Stderr: data},
				})
			} else {
				stream.Send(&pb.ExecOutput{
					Output: &pb.ExecOutput_Stdout{Stdout: data},
				})
			}
		}
		if err != nil {
			return
		}
	}
}

// serverEnvKeys that must never be overridden by the client.
var serverEnvKeys = map[string]bool{
	"PATH": true, "USER": true, "SHELL": true,
}

func mergeEnvLayer(merged map[string]string, env map[string]string) {
	for k, v := range env {
		if serverEnvKeys[k] {
			continue
		}
		merged[k] = v
	}
}

// buildEnv merges environment variables in priority order:
// server OS env → global config env → per-CLI config env → safe client env.
// PATH, USER, and SHELL always come from the server.
func buildEnv(globalEnv, cliEnv, clientEnv map[string]string) []string {
	merged := make(map[string]string)
	for _, entry := range os.Environ() {
		if k, v, ok := strings.Cut(entry, "="); ok {
			merged[k] = v
		}
	}
	mergeEnvLayer(merged, globalEnv)
	mergeEnvLayer(merged, cliEnv)
	mergeEnvLayer(merged, clientEnv)
	result := make([]string, 0, len(merged))
	for k, v := range merged {
		result = append(result, k+"="+v)
	}
	return result
}
