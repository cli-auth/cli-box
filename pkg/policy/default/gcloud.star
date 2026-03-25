def evaluate(ctx):
    return {
        "mounts": [
            {"type": "credential", "store": "gcloud", "target": config_home(ctx["env"]) + "/gcloud"},
        ],
    }

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
