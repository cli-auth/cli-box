## CI / Build

- use jj to manage changes
- use `go fmt ./...` before build

## Core Technology Stack

- use Go 1.26+
- use "github.com/samber/oops" for error handling
- use "github.com/rs/zerolog/log" for logging
- example for oops with zerolog: https://github.com/samber/oops/raw/refs/heads/main/examples/zerolog/example.go

## Coding Style

- Comments describes why this code exists and how to use it, but not what this code does.
- Code logic should be self-descriptive. Use proper naming, functional operators and compositions to help.

### Go Specific

- use `context.Context` to manage cancellation and deadlines across goroutines
- follow structured concurrency: never start a goroutine unless you know who owns it, what tells it to stop, and who waits for it to finish. Avoid bare `go func()` fire-and-forget patterns; prefer `errgroup` or `WaitGroup` so each goroutine has a clear lifetime. Let callers decide concurrency instead of hiding goroutines inside library code. Pass `context.Context` down the call stack and check `ctx.Done()` in long-running or blocking work.
  - use "golang.org/x/sync/errgroup" for cancel-on-error
  - use `sync.WaitGroup` for supervisor-like behavior
- prefer `any` over `interface{}`
