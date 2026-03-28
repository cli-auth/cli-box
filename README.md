# cli-box

**Run CLIs on a trusted machine. Credentials never touch your local box.**

[![GitHub release](https://img.shields.io/github/v/release/cli-auth/cli-box)](https://github.com/cli-auth/cli-box/releases)

cli-box is a secure remote CLI proxy for credential isolation. CLIs like `gh`, `aws`, `gcloud`, and `kubectl` run on a hardened remote server where your credentials live. Each invocation travels over a mutual-TLS gRPC connection and streams output back to your terminal. Credentials, tokens, and config files never leave the trusted host — not even temporarily.

## What it solves

Developer machines get compromised. Cloud credentials stored in `~/.aws`, `~/.config/gh`, and `~/.kube/config` are common targets. Moving those files to a dedicated trusted host eliminates the local attack surface — but then your CLI tools stop working locally.

cli-box bridges that gap. Symlinks on your local machine intercept CLI invocations and proxy them transparently to the remote server. Your workflow stays the same. Your credentials stay safe.

## How it works

```
Local machine (untrusted)             Trusted remote server
─────────────────────────             ─────────────────────
$ gh repo list
  │ (symlink → cli-box)
  │                      mTLS gRPC
  ├──────────────────────────────────▶  bwrap sandbox
  │                                     ├─ gh binary
  │◀─────────── output ───────────────  ├─ credentials (server-side only)
  │                                     └─ your local files via FUSE
$ aws s3 ls
  ├──────────────────────────────────▶  bwrap sandbox
  │◀─────────── output ───────────────  └─ aws binary + credentials
```

Each invocation runs inside an unprivileged sandbox on the server. Your local filesystem is exposed to the sandbox over FUSE so CLIs can read local project files (Terraform configs, Kubernetes manifests, source code) while credentials remain exclusively on the server.

## Features

- **Credential isolation** — credentials never leave the trusted host, not even for a moment
- **Transparent** — symlinks make remote CLIs feel local; no workflow changes required
- **Local file access** — FUSE exposes your working directory to the remote CLI at runtime
- **Zero-trust pairing** — mTLS with TOFU (Trust On First Use); no external CA required
- **Policy engine** — per-CLI Starlark scripts control which credentials mount and where
- **Unprivileged sandbox** — bubblewrap namespaces isolate each session; no root required
- **Audit log** — every CLI invocation is recorded to SQLite with an admin web UI
- **Cross-platform client** — Linux, macOS, Windows

## Installation

Download pre-built binaries from the [Releases](https://github.com/cli-auth/cli-box/releases) page.

| Binary | Install on |
|---|---|
| `cli-box` | The **agent's machine** |
| `cli-box-server` | A **trusted server** accessible from the agent's machine |

Place each binary in a directory on the respective machine's `PATH` (e.g. `/usr/local/bin`).

## Quick start

Before starting the server, install [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) on the trusted remote server.

### 1. Start the server

On your trusted remote server:

```sh
cli-box-server serve
```

On first run the server auto-initializes its PKI state and prints a one-time **pairing token** and **server fingerprint**. You may need this for manual pairing.

```
Pairing token:      cbox_...
Token expires in:   60 minutes
Server fingerprint: SHA256:...
```

### 2. Connect your local machine

Ask an AI agent (OpenClaw, etc.) to fetch `https://<host:port>/skill` — it will read the setup instructions, complete pairing and shim setup, and then invoke the CLIs directly as if they were local.

## Command reference

### cli-box — local machine

| Command | Description |
|---|---|
| `cli-box pair <host:port> --token <token> [--fingerprint <fp>]` | Pair with a remote server |
| `cli-box ping` | Test connection to the paired server |
| `cli-box add [-d dir] <cli> [cli...]` | Create local symlinks for CLIs |
| `cli-box remove [-d dir] [--all] [cli...]` | Remove CLI symlinks |
| `cli-box list [-d dir]` | List managed CLI symlinks |
| `cli-box version` | Print version |

### cli-box-server — remote server

| Command | Description |
|---|---|
| `cli-box-server serve` | Run the server (auto-inits on first run) |
| `cli-box-server init` | Initialize PKI state manually |
| `cli-box-server add-client` | Mint a new pairing token for an additional client |
| `cli-box-server policy list` | List policy scripts |
| `cli-box-server policy create <cli>` | Create a policy script for a new CLI |
| `cli-box-server policy validate` | Validate all policy scripts |
| `cli-box-server policy update-default` | Install missing built-in policies |
| `cli-box-server version` | Print version |

Key `serve` flags:

| Flag | Default | Description |
|---|---|---|
| `--listen` | `:9443` | Address to listen on |
| `--state-dir` | `./state` | PKI state directory |
| `--secure-dir` | `./secure` | Per-CLI credential stores |
| `--policy-dir` | `./policies` | Policy script directory |
| `--sandbox` | `true` | Enable bubblewrap sandbox |

## Policy

Policy scripts are [Starlark](https://github.com/google/starlark-go) files that control which commands are permitted and which credentials mount for each CLI invocation. One file per CLI, stored in `./policies/` on the server.

Install built-in policies:

```sh
cli-box-server policy update-default
```

Example — `policies/gh.star`:

```python
def evaluate(ctx):
    args = ctx["args"]
    env = ctx["env"]
    cred = config_home(env) + "/gh"

    if _has_subcmd(args, ["auth", "token"]):
        return {"deny": True, "message": "gh auth token: direct token access is not permitted"}
    if _refs_cred_dir(args, cred, env):
        return {"deny": True, "message": "referencing gh credential directory is not permitted"}

    return {
        "mounts": [
            {"type": "credential", "store": "gh", "target": cred},
        ],
    }
```

The `store` key names a subdirectory under `--secure-dir`. cli-box-server overlays it onto the CLI's expected config path inside the sandbox. Credentials are bound in at session start and released when the session ends.

### Default policy state

| State | What it does |
|---|---|
| **Audit-only** | All commands allowed; invocations logged for review |
| **Guarded** | Direct token-printing subcommands blocked |
| **Shielded** | + invocations that could expose credential files are denied |
| **Hardened** | Policy is mature and thoroughly reviewed; all known and anticipated credential leakage vectors are denied with high confidence |

| CLI | State | Maturity |
|---|---|---|
| `gh` | Shielded | Needs security review |
| `aws` | Shielded | Needs security review |
| `gcloud` | Shielded | Needs security review |
| `kubectl` | Shielded | Needs security review |

To relax a rule for a specific workflow, edit the relevant `.star` file in `./policies/`.

To add a custom CLI:

```sh
cli-box-server policy create mytool
# edit policies/mytool.star
```

## Admin UI

cli-box-server ships an embedded web UI. When the server starts it prints the admin URL to stdout. Open it to view the audit log, manage pairing, enable or disable CLIs, and monitor active connections.

The server also exposes a `/skill` endpoint that returns setup instructions consumable by AI coding agents (Claude Code, etc.), making it easy to onboard a new machine by asking your agent to fetch and follow them.

## License

License TBD.
