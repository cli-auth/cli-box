package main

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"

	pb "github.com/cli-auth/cli-box/proto"
)

type CommandServer struct {
	pb.UnimplementedCommandServer
	sandboxEnabled bool
	sandboxConfig  *SandboxConfig
}

func (s *CommandServer) Exec(stream pb.Command_ExecServer) error {
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

	if s.sandboxEnabled && s.sandboxConfig != nil {
		args = s.sandboxConfig.WrapCommand(args)
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = start.Cwd
	cmd.Env = buildEnv(start.Env)

	if start.Tty {
		return s.execWithPTY(stream, cmd, start)
	}
	return s.execWithPipes(stream, cmd)
}

func (s *CommandServer) execWithPTY(stream pb.Command_ExecServer, cmd *exec.Cmd, start *pb.ExecStart) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}
	defer ptmx.Close()

	if ws := start.WindowSize; ws != nil {
		pty.Setsize(ptmx, &pty.Winsize{
			Rows: uint16(ws.Rows),
			Cols: uint16(ws.Cols),
		})
	}

	// Stream PTY output to client
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
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
	}()

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
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	wg.Wait()

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

	var wg sync.WaitGroup

	// Stream stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamOutput(stream, stdout, false)
	}()

	// Stream stderr
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamOutput(stream, stderr, true)
	}()

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
		if exitErr, ok := err.(*exec.ExitError); ok {
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

func buildEnv(env map[string]string) []string {
	if len(env) == 0 {
		return os.Environ()
	}
	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, k+"="+v)
	}
	return result
}
