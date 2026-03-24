package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cli-auth/cli-box/pkg/config"
)

func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckDeny(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "deny.star", `
def check(args, env):
    if len(args) > 1 and args[1] == "forbidden":
        return "blocked"
    return None
`)

	engine, err := NewEngine(map[string]config.Rule{
		"deny": {Script: "deny.star"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval([]string{"deny"}, CheckInput{
		Args: []string{"cli", "forbidden"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Denied {
		t.Fatal("expected deny")
	}
	if result.Message != "blocked" {
		t.Fatalf("expected message 'blocked', got %q", result.Message)
	}
}

func TestCheckAllow(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "deny.star", `
def check(args, env):
    if len(args) > 1 and args[1] == "forbidden":
        return "blocked"
    return None
`)

	engine, err := NewEngine(map[string]config.Rule{
		"deny": {Script: "deny.star"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval([]string{"deny"}, CheckInput{
		Args: []string{"cli", "allowed"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Denied {
		t.Fatal("expected allow")
	}
}

func TestCheckShortCircuit(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "first.star", `
def check(args, env):
    return "first denies"
`)
	writeScript(t, dir, "second.star", `
def check(args, env):
    return "second denies"
`)

	engine, err := NewEngine(map[string]config.Rule{
		"first":  {Script: "first.star"},
		"second": {Script: "second.star"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval([]string{"first", "second"}, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Message != "first denies" {
		t.Fatalf("expected first rule to deny, got %q", result.Message)
	}
}

func TestMountsCollection(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "mounts.star", `
def mounts(args, env):
    return [{"source": "/host/certs", "target": "/etc/ssl/certs", "readonly": True}]
`)

	engine, err := NewEngine(map[string]config.Rule{
		"certs": {Script: "mounts.star"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval([]string{"certs"}, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Denied {
		t.Fatal("expected allow")
	}
	if len(result.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(result.Mounts))
	}
	m := result.Mounts[0]
	if m.Source != "/host/certs" || m.Target != "/etc/ssl/certs" || !m.ReadOnly {
		t.Fatalf("unexpected mount: %+v", m)
	}
}

func TestStaticMountsMerge(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "dynamic.star", `
def mounts(args, env):
    return [{"source": "/dynamic", "target": "/mnt/dynamic"}]
`)

	engine, err := NewEngine(map[string]config.Rule{
		"mixed": {
			Script: "dynamic.star",
			ExtraMounts: []config.ExtraMountSpec{
				{Source: "/static", Target: "/mnt/static", ReadOnly: true},
			},
		},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval([]string{"mixed"}, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(result.Mounts))
	}
	// Static mounts come first (appended before dynamic).
	if result.Mounts[0].Source != "/static" {
		t.Fatalf("expected static mount first, got %+v", result.Mounts[0])
	}
	if result.Mounts[1].Source != "/dynamic" {
		t.Fatalf("expected dynamic mount second, got %+v", result.Mounts[1])
	}
}

func TestNoScriptStaticOnly(t *testing.T) {
	engine, err := NewEngine(map[string]config.Rule{
		"static": {
			ExtraMounts: []config.ExtraMountSpec{
				{Source: "/etc/ssl/certs", Target: "/etc/ssl/certs", ReadOnly: true},
			},
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval([]string{"static"}, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(result.Mounts))
	}
}

func TestEnvPassedToScript(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "env.star", `
def check(args, env):
    if env.get("BLOCK") == "true":
        return "env-blocked"
    return None
`)

	engine, err := NewEngine(map[string]config.Rule{
		"env": {Script: "env.star"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval([]string{"env"}, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{"BLOCK": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Denied || result.Message != "env-blocked" {
		t.Fatalf("expected env-blocked deny, got %+v", result)
	}
}

func TestCompileErrorAtStartup(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "bad.star", `def check(args, env`)

	_, err := NewEngine(map[string]config.Rule{
		"bad": {Script: "bad.star"},
	}, dir)
	if err == nil {
		t.Fatal("expected compile error")
	}
}

func TestScriptNotFound(t *testing.T) {
	_, err := NewEngine(map[string]config.Rule{
		"missing": {Script: "nonexistent.star"},
	}, t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing script")
	}
}

func TestCheckBadReturnType(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "bad.star", `
def check(args, env):
    return 42
`)

	engine, err := NewEngine(map[string]config.Rule{
		"bad": {Script: "bad.star"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.Eval([]string{"bad"}, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{},
	})
	if err == nil {
		t.Fatal("expected error for bad return type")
	}
}

func TestCheckWrongParamCount(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "bad.star", `
def check(args):
    return None
`)

	_, err := NewEngine(map[string]config.Rule{
		"bad": {Script: "bad.star"},
	}, dir)
	if err == nil {
		t.Fatal("expected error for wrong param count")
	}
}

func TestUndefinedRule(t *testing.T) {
	engine, err := NewEngine(map[string]config.Rule{}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = engine.Eval([]string{"nonexistent"}, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{},
	})
	if err == nil {
		t.Fatal("expected error for undefined rule")
	}
}

func TestEmptyRules(t *testing.T) {
	engine, err := NewEngine(map[string]config.Rule{}, "")
	if err != nil {
		t.Fatal(err)
	}

	result, err := engine.Eval(nil, CheckInput{
		Args: []string{"cli"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Denied {
		t.Fatal("no rules should mean allow")
	}
}

func TestArgScanning(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "scan.star", `
def check(args, env):
    for i, a in enumerate(args):
        if a in ("--method", "-X") and i + 1 < len(args):
            if args[i + 1] in ("DELETE", "PUT"):
                return "destructive API calls blocked"
    return None
`)

	engine, err := NewEngine(map[string]config.Rule{
		"scan": {Script: "scan.star"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}

	// Should block DELETE
	result, err := engine.Eval([]string{"scan"}, CheckInput{
		Args: []string{"gh", "api", "--method", "DELETE", "/repos/foo"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Denied {
		t.Fatal("expected deny for DELETE")
	}

	// Should allow GET
	result, err = engine.Eval([]string{"scan"}, CheckInput{
		Args: []string{"gh", "api", "--method", "GET", "/repos/foo"},
		Env:  map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Denied {
		t.Fatal("expected allow for GET")
	}
}
