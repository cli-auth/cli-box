# cli-box Setup

Help the user connect this machine to the cli-box server and configure CLI shims.

The server address is the host:port you fetched this skill from.
For example, if you fetched `https://myserver:7777/skill`, the address is `myserver:7777`.

## Server fingerprint

`{{fingerprint}}`

If the fingerprint is not yet available, complete PKI setup in the admin console → Pairing → Initialize.

## Steps

### 1. Check if already paired

```
cli-box ping
```

Exit 0 = already paired and connected — skip to step 4.
Otherwise, continue below.

### 2. Install cli-box

Check if `cli-box` is in PATH. If not, help the user install it from https://github.com/cli-auth/cli-box/release.

### 3. Pair with the server

Ask the user to open the admin console → **Pairing → Generate Pairing Token** and give you the token.

```
cli-box pair <HOST:PORT> --token <TOKEN> --fingerprint {{fingerprint}}
```

### 4. Currently enabled CLIs on this server

{{cliList}}

The user can enable or disable CLIs at any time via the admin console → **Policies**. If the list has changed since this skill was fetched, ask the user to refresh it.

### 5. Set up shims

```
cli-box add {{setupArgs}}
```

### 6. List installed shims

```
cli-box list
```

### 7. Using CLI shims

Each shim is a symlink to `cli-box`. When invoked by its CLI name, `cli-box` connects to the server using the stored mTLS credentials and proxies the command transparently — stdin, stdout, stderr, and exit codes are forwarded as-is.

Run shims exactly as you would the real CLI:

```
gh pr list
terraform plan
kubectl get pods
```

The current working directory and environment are passed to the server, so relative paths and env vars work as expected.

### 8. Remove a shim

```
cli-box remove <name>
```

### 9. Verify

```
cli-box ping
```
