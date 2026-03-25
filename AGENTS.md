## CI / Build

- use jj to manage changes
- use `go fmt ./...` before build

## Core Technology Stack

- use Go 1.26+
- use "github.com/samber/oops" for error handling
- use "github.com/rs/zerolog/log" for logging
- example for oops with zerolog: https://github.com/samber/oops/raw/refs/heads/main/examples/zerolog/example.go
- use Echo for web framework

## Coding Style

- Comments describes why this code exists and how to use it, but not what this code does.
- Code logic should be self-descriptive. Use proper naming, functional operators and compositions to help.

### Go Specific

- use `context.Context` to manage cancellation and deadlines across goroutines
- follow structured concurrency: never start a goroutine unless you know who owns it, what tells it to stop, and who waits for it to finish. Avoid bare `go func()` fire-and-forget patterns; prefer `errgroup` or `WaitGroup` so each goroutine has a clear lifetime. Let callers decide concurrency instead of hiding goroutines inside library code. Pass `context.Context` down the call stack and check `ctx.Done()` in long-running or blocking work.
  - use "golang.org/x/sync/errgroup" for cancel-on-error
  - use `sync.WaitGroup` for supervisor-like behavior
- prefer `any` over `interface{}`

## For Non-Claude Models

### Tone and style
 - Only use emojis if the user explicitly requests it. Avoid using emojis in all communication unless asked.
 - Your responses should be short and concise.
 - When referencing specific functions or pieces of code include the pattern `file_path:line_number` to allow the user to easily navigate to the source code location.

### Output efficiency

IMPORTANT: Go straight to the point. Try the simplest approach first without going in circles. Do not overdo it. Be extra concise.

Keep your text output brief and direct. Lead with the answer or action, not the reasoning. Skip filler words, preamble, and unnecessary transitions. Do not restate what the user said — just do it. When explaining, include only what is necessary for the user to understand.

Focus text output on:
- Decisions that need the user's input
- High-level status updates at natural milestones
- Errors or blockers that change the plan

If you can say it in one sentence, don't use three. Prefer short, direct sentences over long explanations. This does not apply to code or tool calls.
