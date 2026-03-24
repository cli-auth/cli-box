package policy

import (
	"os"

	"github.com/samber/oops"
	"go.starlark.net/starlark"

	"github.com/cli-auth/cli-box/pkg/config"
)

type compiledRule struct {
	check        *starlark.Function
	mounts       *starlark.Function
	staticMounts []config.ExtraMountSpec
}

// Engine loads and evaluates Starlark rule scripts.
type Engine struct {
	rules map[string]*compiledRule
}

// CheckInput holds the arguments for rule evaluation.
type CheckInput struct {
	Args []string
	Env  map[string]string
}

// EvalResult holds the outcome of evaluating all rules for a CLI.
type EvalResult struct {
	Denied  bool
	Message string
	Mounts  []config.ExtraMountSpec
}

// NewEngine compiles all scripts referenced by rules. Called once at startup.
func NewEngine(rules map[string]config.Rule, configDir string) (*Engine, error) {
	compiled := make(map[string]*compiledRule, len(rules))
	for name, rule := range rules {
		cr := &compiledRule{staticMounts: rule.ExtraMounts}

		scriptPath := rule.ResolveScriptPath(configDir)
		if scriptPath == "" {
			compiled[name] = cr
			continue
		}

		src, err := os.ReadFile(scriptPath)
		if err != nil {
			return nil, oops.In("policy").Wrapf(err, "read script for rule %q", name)
		}

		thread := &starlark.Thread{Name: "compile:" + name}
		globals, err := starlark.ExecFile(thread, scriptPath, src, nil)
		if err != nil {
			return nil, oops.In("policy").Wrapf(err, "compile script for rule %q", name)
		}

		if fn, ok := globals["check"]; ok {
			sfn, isFn := fn.(*starlark.Function)
			if !isFn {
				return nil, oops.In("policy").Errorf("rule %q: check is not a function", name)
			}
			if sfn.NumParams() != 2 {
				return nil, oops.In("policy").Errorf("rule %q: check must accept exactly 2 parameters (args, env)", name)
			}
			cr.check = sfn
		}

		if fn, ok := globals["mounts"]; ok {
			sfn, isFn := fn.(*starlark.Function)
			if !isFn {
				return nil, oops.In("policy").Errorf("rule %q: mounts is not a function", name)
			}
			if sfn.NumParams() != 2 {
				return nil, oops.In("policy").Errorf("rule %q: mounts must accept exactly 2 parameters (args, env)", name)
			}
			cr.mounts = sfn
		}

		compiled[name] = cr
	}
	return &Engine{rules: compiled}, nil
}

// Eval runs all rules for a CLI, returning deny/allow + collected mounts.
func (e *Engine) Eval(ruleNames []string, input CheckInput) (EvalResult, error) {
	starArgs := goStringsToStarlarkList(input.Args)
	starEnv := goMapToStarlarkDict(input.Env)
	callArgs := starlark.Tuple{starArgs, starEnv}

	// Phase 1: run check() for each rule, short-circuit on first deny.
	for _, name := range ruleNames {
		rule, ok := e.rules[name]
		if !ok {
			return EvalResult{}, oops.In("policy").Errorf("undefined rule %q", name)
		}
		if rule.check == nil {
			continue
		}

		thread := &starlark.Thread{Name: "check:" + name}
		result, err := starlark.Call(thread, rule.check, callArgs, nil)
		if err != nil {
			return EvalResult{}, oops.In("policy").Wrapf(err, "rule %q check()", name)
		}

		if result.Type() == "NoneType" {
			continue
		}
		if msg, ok := result.(starlark.String); ok {
			return EvalResult{Denied: true, Message: string(msg)}, nil
		}
		return EvalResult{}, oops.In("policy").Errorf("rule %q: check() returned %s, expected string or None", name, result.Type())
	}

	// Phase 2: collect mounts from all rules.
	var mounts []config.ExtraMountSpec
	for _, name := range ruleNames {
		rule := e.rules[name]

		mounts = append(mounts, rule.staticMounts...)

		if rule.mounts == nil {
			continue
		}

		thread := &starlark.Thread{Name: "mounts:" + name}
		result, err := starlark.Call(thread, rule.mounts, callArgs, nil)
		if err != nil {
			return EvalResult{}, oops.In("policy").Wrapf(err, "rule %q mounts()", name)
		}

		list, ok := result.(*starlark.List)
		if !ok {
			return EvalResult{}, oops.In("policy").Errorf("rule %q: mounts() returned %s, expected list", name, result.Type())
		}

		for i := 0; i < list.Len(); i++ {
			dict, ok := list.Index(i).(*starlark.Dict)
			if !ok {
				return EvalResult{}, oops.In("policy").Errorf("rule %q: mounts()[%d] is %s, expected dict", name, i, list.Index(i).Type())
			}
			mount, err := dictToExtraMountSpec(name, i, dict)
			if err != nil {
				return EvalResult{}, err
			}
			mounts = append(mounts, mount)
		}
	}

	return EvalResult{Mounts: mounts}, nil
}

func dictToExtraMountSpec(ruleName string, idx int, d *starlark.Dict) (config.ExtraMountSpec, error) {
	var spec config.ExtraMountSpec

	sourceVal, found, err := d.Get(starlark.String("source"))
	if err != nil || !found {
		return spec, oops.In("policy").Errorf("rule %q: mounts()[%d] missing \"source\"", ruleName, idx)
	}
	s, ok := sourceVal.(starlark.String)
	if !ok {
		return spec, oops.In("policy").Errorf("rule %q: mounts()[%d] \"source\" must be a string", ruleName, idx)
	}
	spec.Source = string(s)

	targetVal, found, err := d.Get(starlark.String("target"))
	if err != nil || !found {
		return spec, oops.In("policy").Errorf("rule %q: mounts()[%d] missing \"target\"", ruleName, idx)
	}
	t, ok := targetVal.(starlark.String)
	if !ok {
		return spec, oops.In("policy").Errorf("rule %q: mounts()[%d] \"target\" must be a string", ruleName, idx)
	}
	spec.Target = string(t)

	if roVal, found, _ := d.Get(starlark.String("readonly")); found {
		if b, ok := roVal.(starlark.Bool); ok {
			spec.ReadOnly = bool(b)
		}
	}

	return spec, nil
}

func goStringsToStarlarkList(ss []string) *starlark.List {
	elems := make([]starlark.Value, len(ss))
	for i, s := range ss {
		elems[i] = starlark.String(s)
	}
	return starlark.NewList(elems)
}

func goMapToStarlarkDict(m map[string]string) *starlark.Dict {
	d := starlark.NewDict(len(m))
	for k, v := range m {
		d.SetKey(starlark.String(k), starlark.String(v))
	}
	return d
}
