_SENSITIVE_KEYS = ["aws_secret_access_key", "aws_session_token", "aws_security_token"]

def evaluate(ctx):
    args = ctx["args"]
    env = ctx["env"]
    cred = home_dir(env) + "/.aws"
    positional = [a for a in args[1:] if not a.startswith("-")]

    if _has_subcmd(args, ["configure", "export-credentials"]):
        return {"deny": True, "message": "aws configure export-credentials: direct credential access is not permitted"}

    n = len(positional)
    for i in range(n - 2):
        if positional[i] == "configure" and positional[i + 1] == "get" and positional[i + 2].lower() in _SENSITIVE_KEYS:
            return {"deny": True, "message": "aws configure get: direct credential access is not permitted"}

    if _refs_cred_dir(args, cred, env):
        return {"deny": True, "message": "referencing aws credential directory is not permitted"}

    return {
        "mounts": [
            {"type": "credential", "store": "aws", "target": cred},
        ],
    }

def _has_subcmd(args, path):
    # Scan non-flag positional args at any position so global flags
    # (e.g. --profile, --region) do not shift subcommand indices.
    positional = [a for a in args[1:] if not a.startswith("-")]
    n = len(path)
    for i in range(len(positional) - n + 1):
        if positional[i:i + n] == path:
            return True
    return False

def _refs_cred_dir(args, cred_base, env):
    # Block any argument that points at or into the credential mount target.
    # Covers both absolute paths and unexpanded tilde paths.
    home = env.get("HOME", "")
    for arg in args[1:]:
        if arg == cred_base or arg.startswith(cred_base + "/"):
            return True
        if home and arg.startswith("~/"):
            expanded = home + arg[1:]
            if expanded == cred_base or expanded.startswith(cred_base + "/"):
                return True
    return False

def home_dir(env):
    home = env.get("HOME")
    if home:
        return home
    return "/tmp"
