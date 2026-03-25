def evaluate(ctx):
    return {
        "mounts": [
            {"type": "credential", "store": "kubectl", "target": home_dir(ctx["env"]) + "/.kube"},
        ],
    }

def home_dir(env):
    home = env.get("HOME")
    if home:
        return home
    return "/tmp"
