package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/cli-auth/cli-box/pkg/admin"
	"github.com/cli-auth/cli-box/pkg/policy"
	pb "github.com/cli-auth/cli-box/proto"
)

type CommandServer struct {
	pb.UnimplementedCommandServer
	ctx            context.Context
	logger         zerolog.Logger
	fuseMountpoint string
	sandboxEnabled bool
	secureDir      string
	mountPolicy    MountPolicy
	policyEngine   *policy.Engine
	fuseReady      chan struct{}
	events         *admin.EventStore
}

func (s *CommandServer) Exec(stream pb.Command_ExecServer) error {
	// Wait for FUSE mount before running any commands
	select {
	case <-s.fuseReady:
	case <-s.ctx.Done():
		return s.ctx.Err()
	}

	requestID := uuid.Must(uuid.NewV7()).String()

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

	s.logger.Debug().Strs("args", args).Str("cwd", start.Cwd).Bool("tty", start.Tty).Bool("sandbox", s.sandboxEnabled).Msg("exec")

	if len(start.Env) > 0 {
		s.events.Add("exec.client_env", "verbose", "client env: "+cliNameFromArgs(args), map[string]string{
			"requestId": requestID,
			"env":       marshalJSON(start.Env),
		})
	}

	policyCtx := &policy.Context{
		Args: args,
		Cwd:  start.Cwd,
		Env:  buildEnvMap(nil, nil, start.Env),
		Original: policy.OriginalContext{
			Args: slicesClone(start.Args),
			Cwd:  start.Cwd,
			Env:  cloneEnvMap(start.Env),
		},
	}
	var credentialMounts, extraMounts []BindMount

	if s.policyEngine != nil {
		if err := s.policyEngine.ApplyBeforePolicies(policyCtx); err != nil {
			s.logger.Warn().Err(err).Msg("before_policies error")
			s.recordExecEvent("exec.denied", "warn", "", requestID, map[string]string{"detail": "policy hook error"})
			return sendDenied(stream, "policy error: "+err.Error())
		}

		cliName := cliNameFromArgs(policyCtx.Args)
		if !s.policyEngine.HasPolicy(cliName) {
			s.recordExecEvent("exec.denied", "warn", cliName, requestID, map[string]string{"detail": "missing policy", "args": marshalJSON(policyCtx.Original.Args)})
			return sendDenied(stream, `no policy for cli "`+cliName+`"`)
		}

		result, err := s.policyEngine.Eval(cliName, policyCtx)
		if err != nil {
			s.logger.Warn().Err(err).Str("cli", cliName).Msg("policy error")
			s.recordExecEvent("exec.denied", "warn", cliName, requestID, map[string]string{"detail": "policy error", "args": marshalJSON(policyCtx.Original.Args)})
			return sendDenied(stream, "policy error: "+err.Error())
		}
		if result.Denied {
			s.logger.Info().Str("cli", cliName).Str("reason", result.Message).Msg("denied by policy")
			s.recordExecEvent("exec.denied", "warn", cliName, requestID, map[string]string{"detail": result.Message, "args": marshalJSON(policyCtx.Original.Args)})
			return sendDenied(stream, result.Message)
		}

		credentialMounts, err = ResolveManagedCredentialMounts(s.secureDir, result.CredentialMounts)
		if err != nil {
			s.logger.Warn().Err(err).Str("cli", cliName).Msg("credential mount error")
			s.recordExecEvent("exec.denied", "warn", cliName, requestID, map[string]string{"detail": "credential mount error", "args": marshalJSON(policyCtx.Original.Args)})
			return sendDenied(stream, "policy error: "+err.Error())
		}
		extraMounts = resolveExtraMounts(result.ExtraMounts)
	}

	args = policyCtx.Args
	cwd := policyCtx.Cwd
	envMap := policyCtx.Env

	// HOME must come from the client, not the server process.
	// Strip server-inherited HOME if the client did not provide one.
	if start.Env["HOME"] == "" {
		delete(envMap, "HOME")
	}

	if s.sandboxEnabled {
		if envMap["HOME"] == "" {
			return sendDenied(stream, "HOME is not set in the client environment; required for sandbox")
		}
		sc := NewSandboxConfig(s.fuseMountpoint, cwd, envMap["HOME"], s.mountPolicy)
		sc.Credentials = credentialMounts
		sc.ExtraMounts = extraMounts
		args = sc.WrapCommand(args)
		cwd = "" // bwrap --chdir handles cwd inside the sandbox
	} else if s.fuseMountpoint != "" {
		cwd = filepath.Join(s.fuseMountpoint, filepath.Clean("/"+cwd))
	}

	s.logger.Debug().Str("cwd", cwd).Strs("args", args).Msg("exec resolved")
	s.recordExecEvent("exec.started", "info", cliNameFromArgs(policyCtx.Original.Args), requestID, map[string]string{"args": marshalJSON(policyCtx.Original.Args)})

	cmd := exec.CommandContext(s.ctx, args[0], args[1:]...)
	cmd.Dir = cwd
	cmd.Env = envMapToList(envMap)

	if start.Tty {
		return s.execWithPTY(stream, cmd, start, requestID)
	}
	return s.execWithPipes(stream, cmd, requestID)
}

func (s *CommandServer) recordExecEvent(eventType, level, cli, requestID string, extra map[string]string) {
	if s.events == nil {
		return
	}

	data := map[string]string{}
	if requestID != "" {
		data["requestId"] = requestID
	}
	if cli != "" {
		data["cli"] = cli
	}
	for k, v := range extra {
		data[k] = v
	}
	s.events.Add(eventType, level, execEventMessage(eventType, cli, extra), data)
}

func execEventMessage(eventType, cli string, extra map[string]string) string {
	verb := strings.TrimPrefix(eventType, "exec.")
	msg := verb
	if cli != "" {
		msg = verb + ": " + cli
	}
	if d := extra["detail"]; d != "" {
		return msg + " — " + d
	}
	if x := extra["exitCode"]; x != "" {
		return msg + " (exit " + x + ")"
	}
	return msg
}

func marshalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func sendReady(stream pb.Command_ExecServer) error {
	return stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Ready{Ready: &pb.ExecReady{}},
	})
}

// sendDenied writes the denial message to stderr and exits with code 1.
func sendDenied(stream pb.Command_ExecServer, msg string) error {
	stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Stderr{Stderr: []byte("denied: " + msg + "\n")},
	})
	return stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
	})
}

func resolveExtraMounts(specs []policy.MountSpec) []BindMount {
	mounts := make([]BindMount, len(specs))
	for i, s := range specs {
		mounts[i] = BindMount{
			Source:   s.Source,
			Target:   s.Target,
			ReadOnly: s.ReadOnly,
		}
	}
	return mounts
}

func cliNameFromArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return filepath.Base(args[0])
}

func (s *CommandServer) execWithPTY(stream pb.Command_ExecServer, cmd *exec.Cmd, start *pb.ExecStart, requestID string) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		s.logger.Debug().Err(err).Msg("pty.Start failed")
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}
	defer ptmx.Close()
	s.logger.Debug().Int("pid", cmd.Process.Pid).Msg("pty started")

	if err := sendReady(stream); err != nil {
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
		s.logger.Debug().Err(err).Msg("pty cmd.Wait")
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	wg.Wait()
	s.logger.Debug().Int("exitCode", exitCode).Msg("pty done")
	s.recordExecEvent("exec.finished", "info", cliNameFromArgs(start.Args), requestID, map[string]string{"exitCode": strconv.Itoa(exitCode)})

	return stream.Send(&pb.ExecOutput{
		Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: int32(exitCode)}},
	})
}

func (s *CommandServer) execWithPipes(stream pb.Command_ExecServer, cmd *exec.Cmd, requestID string) error {
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
		s.recordExecEvent("exec.failed", "error", cliNameFromArgs(cmd.Args), requestID, map[string]string{"detail": err.Error()})
		return stream.Send(&pb.ExecOutput{
			Output: &pb.ExecOutput_Exit{Exit: &pb.ExecExit{ExitCode: 1}},
		})
	}

	if err := sendReady(stream); err != nil {
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
	s.recordExecEvent("exec.finished", "info", cliNameFromArgs(cmd.Args), requestID, map[string]string{"exitCode": strconv.Itoa(exitCode)})

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

// serverEnvKeys are copied from the server's environment into every exec and
// cannot be overridden by the client. Everything else the server carries is
// intentionally excluded to prevent secret leakage (tokens, cloud creds, etc.).
var serverEnvKeys = map[string]bool{
	// Runtime identity — must come from the server.
	"PATH": true, "USER": true, "SHELL": true,
	// Loader attack surface — never let the client set these.
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true,
	"LD_DEBUG": true, "LD_PROFILE": true,
	// Outbound networking — proxies and TLS trust are server infrastructure.
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"REQUESTS_CA_BUNDLE": true, "CURL_CA_BUNDLE": true,
}

func mergeEnvLayer(merged map[string]string, env map[string]string) {
	for k, v := range env {
		if serverEnvKeys[k] {
			continue
		}
		merged[k] = v
	}
}

func mergeEnvDefaults(merged map[string]string, env map[string]string) {
	for k, v := range env {
		if serverEnvKeys[k] {
			continue
		}
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
}

// buildEnv merges environment variables in priority order:
// server OS env → global config env → per-CLI config env → safe client env.
// PATH, USER, and SHELL always come from the server.
func buildEnv(globalEnv, cliEnv, clientEnv map[string]string) []string {
	return envMapToList(buildEnvMap(globalEnv, cliEnv, clientEnv))
}

func buildEnvMap(globalEnv, cliEnv, clientEnv map[string]string) map[string]string {
	// Seed only with the server keys that CLIs actually need.
	// Using os.Environ() would leak every secret the server carries
	// (cloud credentials, tokens, etc.) into the executed process.
	merged := make(map[string]string)
	for _, entry := range os.Environ() {
		if k, v, ok := strings.Cut(entry, "="); ok {
			if serverEnvKeys[k] {
				merged[k] = v
			}
		}
	}
	mergeEnvLayer(merged, globalEnv)
	mergeEnvLayer(merged, cliEnv)
	mergeEnvLayer(merged, clientEnv)
	return merged
}

func envMapToList(env map[string]string) []string {
	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, k+"="+v)
	}
	return result
}

func cloneEnvMap(env map[string]string) map[string]string {
	cloned := make(map[string]string, len(env))
	for k, v := range env {
		cloned[k] = v
	}
	return cloned
}

func slicesClone[T any](values []T) []T {
	cloned := make([]T, len(values))
	copy(cloned, values)
	return cloned
}
