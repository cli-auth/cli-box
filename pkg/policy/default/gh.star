def evaluate(ctx):
    args = ctx["args"]
    env = ctx["env"]
    cred = config_home(env) + "/gh"

    if _has_subcmd(args, ["auth", "token"]):
        return {"deny": True, "message": "gh auth token: direct token access is not permitted"}
    if _has_subcmd(args, ["auth", "status"]) and ("--show-token" in args or "-t" in args):
        return {"deny": True, "message": "gh auth status --show-token: direct token access is not permitted"}
    if _has_subcmd(args, ["gist", "create"]):
        return {"deny": True, "message": "gh gist create: file upload to external service is not permitted"}
    if _has_subcmd(args, ["release", "upload"]):
        return {"deny": True, "message": "gh release upload: file upload to external service is not permitted"}
    if _refs_cred_dir(args, cred, env):
        return {"deny": True, "message": "referencing gh credential directory is not permitted"}

    return {
        "mounts": [
            {"type": "credential", "store": "gh", "target": cred},
        ],
    }

def _has_subcmd(args, path):
    # Scan non-flag positional args at any position so global flags
    # (e.g. --no-update-notifier) do not shift subcommand indices.
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

def config_home(env):
    xdg = env.get("XDG_CONFIG_HOME")
    if xdg:
        return xdg
    return home_dir(env) + "/.config"
