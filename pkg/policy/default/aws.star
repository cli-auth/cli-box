def evaluate(ctx):
    return {
        "mounts": [
            {"type": "credential", "store": "aws", "target": home_dir(ctx["env"]) + "/.aws"},
        ],
    }

def home_dir(env):
    home = env.get("HOME")
    if home:
        return home
    return "/tmp"
