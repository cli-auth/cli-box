## CI / Build

- use nix to manage development environment
- use `go fmt ./...` before build

## Core Technology Stack

- use Go 1.26+

## Coding Style

- Comments describes why this code exists and how to use it, but not what this code does.
- Code logic should be self-descriptive. Use proper naming, functional operators and compositions to help.

### Go Specific

- prefer `any` over `interface{}`
