package policy

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/oops"
	"go.starlark.net/starlark"
)

type compiledPolicy struct {
	evaluate *starlark.Function
}

type compiledHook struct {
	beforePolicies *starlark.Function
}

// OriginalContext captures the client request before any policy mutation.
type OriginalContext struct {
	Args []string
	Cwd  string
	Env  map[string]string
}

// Context holds the mutable execution state shared with hooks and policies.
type Context struct {
	Args     []string
	Cwd      string
	Env      map[string]string
	Original OriginalContext
}

// ManagedCredentialMount requests a secureDir-backed credential store.
type ManagedCredentialMount struct {
	Store    string
	Target   string
	ReadOnly bool
	File     bool
}

// MountSpec holds a validated raw bind mount request.
type MountSpec struct {
	Source   string
	Target   string
	ReadOnly bool
}

// EvalResult holds the outcome of evaluating a CLI policy.
type EvalResult struct {
	Denied           bool
	Message          string
	CredentialMounts []ManagedCredentialMount
	ExtraMounts      []MountSpec
}

// Engine loads policy scripts from a policy directory.
type Engine struct {
	hook     compiledHook
	policies map[string]*compiledPolicy
}

//go:embed default/*.star
var templateFS embed.FS

// NewEngine loads and compiles the policy directory.
func NewEngine(policyDir string) (*Engine, error) {
	if err := ensurePolicyDir(policyDir); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return nil, oops.In("policy").Wrapf(err, "read policy dir")
	}

	engine := &Engine{policies: make(map[string]*compiledPolicy)}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".star" {
			continue
		}

		path := filepath.Join(policyDir, entry.Name())
		globals, err := execPolicyFile(path)
		if err != nil {
			return nil, err
		}

		if entry.Name() == "_init.star" {
			hook, err := compileHook(entry.Name(), globals)
			if err != nil {
				return nil, err
			}
			engine.hook = hook
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".star")
		policy, err := compilePolicy(name, globals)
		if err != nil {
			return nil, err
		}
		engine.policies[name] = policy
	}

	return engine, nil
}

// HasPolicy reports whether a per-CLI script exists.
func (e *Engine) HasPolicy(cli string) bool {
	_, ok := e.policies[cli]
	return ok
}

// PolicyCount returns the number of compiled per-CLI policies.
func (e *Engine) PolicyCount() int {
	return len(e.policies)
}

// ListPolicyNames returns compiled policy names in stable order.
func (e *Engine) ListPolicyNames() []string {
	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ApplyBeforePolicies runs the optional before_policies hook.
func (e *Engine) ApplyBeforePolicies(ctx *Context) error {
	return callHook("before_policies", e.hook.beforePolicies, ctx)
}

// Eval runs the per-CLI policy.
func (e *Engine) Eval(cli string, ctx *Context) (EvalResult, error) {
	policy, ok := e.policies[cli]
	if !ok {
		return EvalResult{}, oops.In("policy").Errorf("no policy for cli %q", cli)
	}
	if policy.evaluate == nil {
		return EvalResult{}, oops.In("policy").Errorf("cli %q: evaluate is required", cli)
	}

	starCtx, err := newMutableContext(ctx)
	if err != nil {
		return EvalResult{}, err
	}

	thread := &starlark.Thread{Name: "evaluate:" + cli}
	value, err := starlark.Call(thread, policy.evaluate, starlark.Tuple{starCtx}, nil)
	if err != nil {
		return EvalResult{}, oops.In("policy").Wrapf(err, "cli %q evaluate()", cli)
	}

	if err := updateContextFromDict(starCtx, ctx); err != nil {
		return EvalResult{}, err
	}

	if value == starlark.None {
		return EvalResult{}, nil
	}

	dict, ok := value.(*starlark.Dict)
	if !ok {
		return EvalResult{}, oops.In("policy").Errorf("cli %q: evaluate() returned %s, expected dict or None", cli, value.Type())
	}

	return dictToEvalResult(cli, dict)
}

func ensurePolicyDir(policyDir string) error {
	if policyDir == "" {
		return oops.In("policy").Errorf("policy dir is required")
	}
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		return oops.In("policy").Wrapf(err, "create policy dir")
	}

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return oops.In("policy").Wrapf(err, "read policy dir")
	}
	if len(entries) != 0 {
		return nil
	}

	created, err := UpdateDefaultPolicies(policyDir)
	if err != nil {
		return err
	}
	_ = created
	return nil
}

func execPolicyFile(path string) (starlark.StringDict, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, oops.In("policy").Wrapf(err, "read script %q", filepath.Base(path))
	}

	thread := &starlark.Thread{Name: "compile:" + filepath.Base(path)}
	globals, err := starlark.ExecFile(thread, path, src, nil)
	if err != nil {
		return nil, oops.In("policy").Wrapf(err, "compile script %q", filepath.Base(path))
	}
	return globals, nil
}

func compileHook(name string, globals starlark.StringDict) (compiledHook, error) {
	hook := compiledHook{}

	if fn, ok := globals["before_policies"]; ok {
		sfn, ok := fn.(*starlark.Function)
		if !ok {
			return compiledHook{}, oops.In("policy").Errorf("%s: before_policies is not a function", name)
		}
		if sfn.NumParams() != 1 {
			return compiledHook{}, oops.In("policy").Errorf("%s: before_policies must accept exactly 1 parameter (ctx)", name)
		}
		hook.beforePolicies = sfn
	}

	return hook, nil
}

func compilePolicy(name string, globals starlark.StringDict) (*compiledPolicy, error) {
	fn, ok := globals["evaluate"]
	if !ok {
		return nil, oops.In("policy").Errorf("cli %q: evaluate is required", name)
	}
	sfn, ok := fn.(*starlark.Function)
	if !ok {
		return nil, oops.In("policy").Errorf("cli %q: evaluate is not a function", name)
	}
	if sfn.NumParams() != 1 {
		return nil, oops.In("policy").Errorf("cli %q: evaluate must accept exactly 1 parameter (ctx)", name)
	}
	return &compiledPolicy{evaluate: sfn}, nil
}

func callHook(phase string, fn *starlark.Function, ctx *Context) error {
	if fn == nil {
		return nil
	}

	starCtx, err := newMutableContext(ctx)
	if err != nil {
		return err
	}

	thread := &starlark.Thread{Name: phase}
	value, err := starlark.Call(thread, fn, starlark.Tuple{starCtx}, nil)
	if err != nil {
		return oops.In("policy").Wrapf(err, "%s()", phase)
	}
	if value != starlark.None {
		return oops.In("policy").Errorf("%s() must return None", phase)
	}

	return updateContextFromDict(starCtx, ctx)
}

func newMutableContext(ctx *Context) (*starlark.Dict, error) {
	original, err := newFrozenOriginal(ctx.Original)
	if err != nil {
		return nil, err
	}

	dict := starlark.NewDict(4)
	if err := dict.SetKey(starlark.String("args"), goStringsToStarlarkList(ctx.Args)); err != nil {
		return nil, err
	}
	if err := dict.SetKey(starlark.String("cwd"), starlark.String(ctx.Cwd)); err != nil {
		return nil, err
	}
	if err := dict.SetKey(starlark.String("env"), goMapToMutableStarlarkDict(ctx.Env)); err != nil {
		return nil, err
	}
	if err := dict.SetKey(starlark.String("original"), original); err != nil {
		return nil, err
	}
	return dict, nil
}

func newFrozenOriginal(original OriginalContext) (*starlark.Dict, error) {
	dict := starlark.NewDict(3)
	args := goStringsToStarlarkList(original.Args)
	args.Freeze()
	env := goMapToMutableStarlarkDict(original.Env)
	env.Freeze()
	if err := dict.SetKey(starlark.String("args"), args); err != nil {
		return nil, err
	}
	if err := dict.SetKey(starlark.String("cwd"), starlark.String(original.Cwd)); err != nil {
		return nil, err
	}
	if err := dict.SetKey(starlark.String("env"), env); err != nil {
		return nil, err
	}
	dict.Freeze()
	return dict, nil
}

func updateContextFromDict(dict *starlark.Dict, ctx *Context) error {
	argsVal, found, err := dict.Get(starlark.String("args"))
	if err != nil || !found {
		return oops.In("policy").Errorf(`ctx.args is required`)
	}
	args, err := starlarkListToStrings("ctx", "args", argsVal)
	if err != nil {
		return err
	}

	cwdVal, found, err := dict.Get(starlark.String("cwd"))
	if err != nil || !found {
		return oops.In("policy").Errorf(`ctx.cwd is required`)
	}
	cwdString, ok := cwdVal.(starlark.String)
	if !ok {
		return oops.In("policy").Errorf(`ctx.cwd must be a string`)
	}

	envVal, found, err := dict.Get(starlark.String("env"))
	if err != nil || !found {
		return oops.In("policy").Errorf(`ctx.env is required`)
	}
	env, err := starlarkDictToStrings("ctx", "env", envVal)
	if err != nil {
		return err
	}

	originalVal, found, err := dict.Get(starlark.String("original"))
	if err != nil || !found {
		return oops.In("policy").Errorf(`ctx.original is required`)
	}
	if err := ensureOriginalUnchanged(originalVal, ctx.Original); err != nil {
		return err
	}

	ctx.Args = args
	ctx.Cwd = string(cwdString)
	ctx.Env = env
	return nil
}

func ensureOriginalUnchanged(value starlark.Value, original OriginalContext) error {
	dict, ok := value.(*starlark.Dict)
	if !ok {
		return oops.In("policy").Errorf(`ctx.original must be a dict`)
	}

	argsVal, found, err := dict.Get(starlark.String("args"))
	if err != nil || !found {
		return oops.In("policy").Errorf(`ctx.original.args is required`)
	}
	args, err := starlarkListToStrings("ctx.original", "args", argsVal)
	if err != nil {
		return err
	}

	cwdVal, found, err := dict.Get(starlark.String("cwd"))
	if err != nil || !found {
		return oops.In("policy").Errorf(`ctx.original.cwd is required`)
	}
	cwd, ok := cwdVal.(starlark.String)
	if !ok {
		return oops.In("policy").Errorf(`ctx.original.cwd must be a string`)
	}

	envVal, found, err := dict.Get(starlark.String("env"))
	if err != nil || !found {
		return oops.In("policy").Errorf(`ctx.original.env is required`)
	}
	env, err := starlarkDictToStrings("ctx.original", "env", envVal)
	if err != nil {
		return err
	}

	if !slices.Equal(args, original.Args) || string(cwd) != original.Cwd || !mapsEqual(env, original.Env) {
		return oops.In("policy").Errorf(`ctx.original is read-only`)
	}
	return nil
}

func dictToEvalResult(cli string, d *starlark.Dict) (EvalResult, error) {
	result := EvalResult{}

	if denyVal, found, _ := d.Get(starlark.String("deny")); found {
		deny, ok := denyVal.(starlark.Bool)
		if !ok {
			return EvalResult{}, oops.In("policy").Errorf(`cli %q: evaluate().deny must be a bool`, cli)
		}
		result.Denied = bool(deny)
	}

	if msgVal, found, _ := d.Get(starlark.String("message")); found {
		msg, ok := msgVal.(starlark.String)
		if !ok {
			return EvalResult{}, oops.In("policy").Errorf(`cli %q: evaluate().message must be a string`, cli)
		}
		result.Message = string(msg)
	}

	if mountsVal, found, _ := d.Get(starlark.String("mounts")); found {
		list, ok := mountsVal.(*starlark.List)
		if !ok {
			return EvalResult{}, oops.In("policy").Errorf(`cli %q: evaluate().mounts must be a list`, cli)
		}
		for i := 0; i < list.Len(); i++ {
			item, ok := list.Index(i).(*starlark.Dict)
			if !ok {
				return EvalResult{}, oops.In("policy").Errorf("cli %q: mounts[%d] is %s, expected dict", cli, i, list.Index(i).Type())
			}
			mountType, store, source, target, readonly, file, err := dictToMountSpec(cli, i, item)
			if err != nil {
				return EvalResult{}, err
			}
			switch mountType {
			case "credential":
				result.CredentialMounts = append(result.CredentialMounts, ManagedCredentialMount{
					Store:    store,
					Target:   target,
					ReadOnly: readonly,
					File:     file,
				})
			case "bind":
				result.ExtraMounts = append(result.ExtraMounts, MountSpec{
					Source:   source,
					Target:   target,
					ReadOnly: readonly,
				})
			}
		}
	}

	return result, nil
}

func dictToMountSpec(cli string, idx int, d *starlark.Dict) (mountType, store, source, target string, readonly, file bool, err error) {
	typeVal, found, _ := d.Get(starlark.String("type"))
	if !found {
		err = oops.In("policy").Errorf("cli %q: mounts[%d] missing \"type\"", cli, idx)
		return
	}
	typeString, ok := typeVal.(starlark.String)
	if !ok {
		err = oops.In("policy").Errorf("cli %q: mounts[%d] \"type\" must be a string", cli, idx)
		return
	}
	mountType = string(typeString)
	if mountType != "credential" && mountType != "bind" {
		err = oops.In("policy").Errorf("cli %q: mounts[%d] \"type\" must be \"credential\" or \"bind\"", cli, idx)
		return
	}

	if value, found, _ := d.Get(starlark.String("readonly")); found {
		b, ok := value.(starlark.Bool)
		if !ok {
			err = oops.In("policy").Errorf("cli %q: mounts[%d] \"readonly\" must be a bool", cli, idx)
			return
		}
		readonly = bool(b)
	}

	if value, found, _ := d.Get(starlark.String("file")); found {
		b, ok := value.(starlark.Bool)
		if !ok {
			err = oops.In("policy").Errorf("cli %q: mounts[%d] \"file\" must be a bool", cli, idx)
			return
		}
		file = bool(b)
	}

	targetVal, found, getErr := d.Get(starlark.String("target"))
	if getErr != nil || !found {
		err = oops.In("policy").Errorf("cli %q: mounts[%d] missing \"target\"", cli, idx)
		return
	}
	targetString, ok := targetVal.(starlark.String)
	if !ok {
		err = oops.In("policy").Errorf("cli %q: mounts[%d] \"target\" must be a string", cli, idx)
		return
	}
	target, err = validatePath(cli, "target", string(targetString))
	if err != nil {
		return
	}

	switch mountType {
	case "credential":
		storeVal, found, _ := d.Get(starlark.String("store"))
		if !found {
			err = oops.In("policy").Errorf("cli %q: mounts[%d] missing \"store\"", cli, idx)
			return
		}
		storeString, ok := storeVal.(starlark.String)
		if !ok {
			err = oops.In("policy").Errorf("cli %q: mounts[%d] \"store\" must be a string", cli, idx)
			return
		}
		store = string(storeString)
		if !validStoreName(store) {
			err = oops.In("policy").Errorf("cli %q: mounts[%d] \"store\" must be a plain name", cli, idx)
		}
	case "bind":
		sourceVal, found, _ := d.Get(starlark.String("source"))
		if !found {
			err = oops.In("policy").Errorf("cli %q: mounts[%d] missing \"source\"", cli, idx)
			return
		}
		sourceString, ok := sourceVal.(starlark.String)
		if !ok {
			err = oops.In("policy").Errorf("cli %q: mounts[%d] \"source\" must be a string", cli, idx)
			return
		}
		source, err = validatePath(cli, "source", string(sourceString))
	}

	return
}

func starlarkListToStrings(scope, field string, value starlark.Value) ([]string, error) {
	switch list := value.(type) {
	case *starlark.List:
		result := make([]string, list.Len())
		for i := 0; i < list.Len(); i++ {
			s, ok := list.Index(i).(starlark.String)
			if !ok {
				return nil, oops.In("policy").Errorf("%s.%s[%d] must be a string", scope, field, i)
			}
			result[i] = string(s)
		}
		return result, nil
	case starlark.Tuple:
		result := make([]string, len(list))
		for i, item := range list {
			s, ok := item.(starlark.String)
			if !ok {
				return nil, oops.In("policy").Errorf("%s.%s[%d] must be a string", scope, field, i)
			}
			result[i] = string(s)
		}
		return result, nil
	default:
		return nil, oops.In("policy").Errorf("%s.%s must be a list", scope, field)
	}
}

func starlarkDictToStrings(scope, field string, value starlark.Value) (map[string]string, error) {
	dict, ok := value.(*starlark.Dict)
	if !ok {
		return nil, oops.In("policy").Errorf("%s.%s must be a dict", scope, field)
	}

	result := make(map[string]string, dict.Len())
	for _, item := range dict.Items() {
		key, ok := item[0].(starlark.String)
		if !ok {
			return nil, oops.In("policy").Errorf("%s.%s keys must be strings", scope, field)
		}
		val, ok := item[1].(starlark.String)
		if !ok {
			return nil, oops.In("policy").Errorf("%s.%s[%q] must be a string", scope, field, string(key))
		}
		result[string(key)] = string(val)
	}
	return result, nil
}

func validatePath(cli, field, value string) (string, error) {
	if value == "" {
		return "", oops.In("policy").Errorf("cli %q: mount %q must not be empty", cli, field)
	}
	if !filepath.IsAbs(value) {
		return "", oops.In("policy").Errorf("cli %q: mount %q must be an absolute path", cli, field)
	}
	cleaned := filepath.Clean(value)
	if cleaned != value {
		return "", oops.In("policy").Errorf("cli %q: mount %q must be a clean path without traversal segments", cli, field)
	}
	for _, segment := range strings.Split(filepath.ToSlash(value), "/") {
		if segment == ".." {
			return "", oops.In("policy").Errorf("cli %q: mount %q must not contain traversal segments", cli, field)
		}
	}
	return cleaned, nil
}

func validStoreName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, `/\`)
}

func goStringsToStarlarkList(ss []string) *starlark.List {
	elems := make([]starlark.Value, len(ss))
	for i, s := range ss {
		elems[i] = starlark.String(s)
	}
	return starlark.NewList(elems)
}

func goMapToMutableStarlarkDict(m map[string]string) *starlark.Dict {
	d := starlark.NewDict(len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		d.SetKey(starlark.String(k), starlark.String(m[k]))
	}
	return d
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func defaultPolicyFiles() (map[string][]byte, error) {
	files := map[string][]byte{}

	entries, err := fs.ReadDir(templateFS, "default")
	if err != nil {
		return nil, oops.In("policy").Wrapf(err, "list embedded policy templates")
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".star" {
			continue
		}

		content, err := readTemplateFile(filepath.Join("default", entry.Name()))
		if err != nil {
			return nil, err
		}
		files[entry.Name()] = content
	}

	return files, nil
}

func readTemplateFile(path string) ([]byte, error) {
	content, err := templateFS.ReadFile(path)
	if err != nil {
		return nil, oops.In("policy").Wrapf(err, "read embedded policy template %q", filepath.Base(path))
	}
	return content, nil
}
