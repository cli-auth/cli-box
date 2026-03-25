package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writeScript(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNewEngineScaffoldsEmptyPolicyDir(t *testing.T) {
	dir := t.TempDir()

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.HasPolicy("gh") {
		t.Fatal("expected scaffolded gh policy")
	}

	for _, name := range []string{"_init.star", "gh.star", "aws.star", "gcloud.star", "kubectl.star"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected scaffolded file %q: %v", name, err)
		}
	}
}

func TestBeforePoliciesMutatesContext(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "_init.star", `
def before_policies(ctx):
    ctx["args"] = ["gh", "status"]
    ctx["cwd"] = "/work"
    ctx["env"]["PAGER"] = "less"
`)
	writeScript(t, dir, "gh.star", `
def evaluate(ctx):
    return None
`)

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &Context{
		Args: []string{"wrapper"},
		Cwd:  "/tmp",
		Env:  map[string]string{"HOME": "/home/test"},
		Original: OriginalContext{
			Args: []string{"wrapper"},
			Cwd:  "/tmp",
			Env:  map[string]string{"HOME": "/home/test"},
		},
	}

	if err := engine.ApplyBeforePolicies(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ctx.Args) != 2 || ctx.Args[0] != "gh" {
		t.Fatalf("unexpected args: %+v", ctx.Args)
	}
	if ctx.Cwd != "/work" {
		t.Fatalf("unexpected cwd: %q", ctx.Cwd)
	}
	if ctx.Env["PAGER"] != "less" {
		t.Fatalf("unexpected env: %+v", ctx.Env)
	}
}

func TestBeforePoliciesRejectsOriginalMutation(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "_init.star", `
def before_policies(ctx):
    ctx["original"]["cwd"] = "/evil"
`)
	writeScript(t, dir, "gh.star", `
def evaluate(ctx):
    return None
`)

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &Context{
		Args: []string{"gh"},
		Cwd:  "/tmp",
		Env:  map[string]string{"HOME": "/home/test"},
		Original: OriginalContext{
			Args: []string{"gh"},
			Cwd:  "/tmp",
			Env:  map[string]string{"HOME": "/home/test"},
		},
	}

	if err := engine.ApplyBeforePolicies(ctx); err == nil {
		t.Fatal("expected original mutation error")
	}
}

func TestEvalDenyAndContextMutation(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "gh.star", `
def evaluate(ctx):
    ctx["cwd"] = "/workspace"
    if len(ctx["args"]) > 1 and ctx["args"][1] == "forbidden":
        return {"deny": True, "message": "blocked"}
    return None
`)

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &Context{
		Args: []string{"gh", "forbidden"},
		Cwd:  "/tmp",
		Env:  map[string]string{},
		Original: OriginalContext{
			Args: []string{"gh", "forbidden"},
			Cwd:  "/tmp",
			Env:  map[string]string{},
		},
	}

	result, err := engine.Eval("gh", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Denied || result.Message != "blocked" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if ctx.Cwd != "/workspace" {
		t.Fatalf("expected cwd mutation, got %q", ctx.Cwd)
	}
}

func TestEvalCollectsTaggedMounts(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "gh.star", `
def evaluate(ctx):
    return {
        "mounts": [
            {"type": "credential", "store": "gh", "target": "/home/test/.config/gh"},
            {"type": "bind", "source": "/etc/ssl/certs", "target": "/etc/ssl/certs", "readonly": True},
        ],
    }
`)

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval("gh", &Context{
		Args: []string{"gh"},
		Cwd:  "/tmp",
		Env:  map[string]string{"HOME": "/home/test"},
		Original: OriginalContext{
			Args: []string{"gh"},
			Cwd:  "/tmp",
			Env:  map[string]string{"HOME": "/home/test"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CredentialMounts) != 1 || result.CredentialMounts[0].Store != "gh" {
		t.Fatalf("unexpected credential mounts: %+v", result.CredentialMounts)
	}
	if len(result.ExtraMounts) != 1 || result.ExtraMounts[0].Source != "/etc/ssl/certs" {
		t.Fatalf("unexpected bind mounts: %+v", result.ExtraMounts)
	}
}

func TestEvalRejectsInvalidMountType(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "gh.star", `
def evaluate(ctx):
    return {"mounts": [{"type": "weird", "target": "/tmp"}]}
`)

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.Eval("gh", &Context{
		Args: []string{"gh"},
		Cwd:  "/tmp",
		Env:  map[string]string{},
		Original: OriginalContext{
			Args: []string{"gh"},
			Cwd:  "/tmp",
			Env:  map[string]string{},
		},
	})
	if err == nil {
		t.Fatal("expected invalid mount type error")
	}
}

func TestInitHookWithoutBeforePoliciesIsOptional(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "_init.star", `# empty init`)
	writeScript(t, dir, "gh.star", `
def evaluate(ctx):
    return None
`)

	engine, err := NewEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &Context{
		Args: []string{"gh"},
		Cwd:  "/tmp",
		Env:  map[string]string{},
		Original: OriginalContext{
			Args: []string{"gh"},
			Cwd:  "/tmp",
			Env:  map[string]string{},
		},
	}

	if err := engine.ApplyBeforePolicies(ctx); err != nil {
		t.Fatal(err)
	}
}
