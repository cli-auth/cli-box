package policy

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/oops"
)

const createPolicyTemplate = `def evaluate(ctx):
    return None
`

// ListDir returns policy script filenames in stable display order.
func ListDir(policyDir string) ([]string, error) {
	entries, err := listPolicyEntries(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, oops.In("policy").Wrapf(err, "read policy dir")
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sortPolicyNames(names)
	return names, nil
}

// ValidateDir compiles policy scripts without scaffolding missing files.
func ValidateDir(policyDir string) error {
	if policyDir == "" {
		return oops.In("policy").Errorf("policy dir is required")
	}

	entries, err := listPolicyEntries(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return oops.In("policy").Errorf("policy dir %q does not exist", policyDir)
		}
		return oops.In("policy").Wrapf(err, "read policy dir")
	}
	if len(entries) == 0 {
		return oops.In("policy").Errorf("policy dir %q does not contain any .star files", policyDir)
	}

	return validateEntries(policyDir, entries)
}

// UpdateDefaultPolicies writes missing embedded default scripts without overwriting existing files.
func UpdateDefaultPolicies(policyDir string) ([]string, error) {
	if policyDir == "" {
		return nil, oops.In("policy").Errorf("policy dir is required")
	}
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		return nil, oops.In("policy").Wrapf(err, "create policy dir")
	}

	files, err := defaultPolicyFiles()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sortPolicyNames(names)

	created := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(policyDir, name)
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return nil, oops.In("policy").Wrapf(err, "stat policy file %q", name)
		}

		if err := os.WriteFile(path, files[name], 0o600); err != nil {
			return nil, oops.In("policy").Wrapf(err, "write default policy file %q", name)
		}
		created = append(created, name)
	}

	return created, nil
}

// CreatePolicy creates a per-CLI policy script from the embedded generic template.
func CreatePolicy(policyDir, cli string) (string, error) {
	if policyDir == "" {
		return "", oops.In("policy").Errorf("policy dir is required")
	}
	if !validPolicyName(cli) {
		return "", oops.In("policy").Errorf("invalid policy name %q", cli)
	}
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		return "", oops.In("policy").Wrapf(err, "create policy dir")
	}

	name := cli + ".star"
	path := filepath.Join(policyDir, name)
	if _, err := os.Stat(path); err == nil {
		return "", oops.In("policy").Errorf("policy %q already exists", cli)
	} else if !os.IsNotExist(err) {
		return "", oops.In("policy").Wrapf(err, "stat policy file %q", name)
	}

	if err := os.WriteFile(path, []byte(createPolicyTemplate), 0o600); err != nil {
		return "", oops.In("policy").Wrapf(err, "write policy file %q", name)
	}
	return name, nil
}

func listPolicyEntries(policyDir string) ([]fs.DirEntry, error) {
	if policyDir == "" {
		return nil, oops.In("policy").Errorf("policy dir is required")
	}

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		return nil, err
	}

	policyEntries := make([]fs.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".star" {
			continue
		}
		policyEntries = append(policyEntries, entry)
	}
	return policyEntries, nil
}

func validateEntries(policyDir string, entries []fs.DirEntry) error {
	for _, entry := range entries {
		path := filepath.Join(policyDir, entry.Name())
		globals, err := execPolicyFile(path)
		if err != nil {
			return err
		}

		if entry.Name() == "_init.star" {
			if _, err := compileHook(entry.Name(), globals); err != nil {
				return err
			}
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".star")
		if _, err := compilePolicy(name, globals); err != nil {
			return err
		}
	}

	return nil
}

func sortPolicyNames(names []string) {
	sort.Slice(names, func(i, j int) bool {
		if names[i] == "_init.star" {
			return true
		}
		if names[j] == "_init.star" {
			return false
		}
		return names[i] < names[j]
	})
}

func validPolicyName(name string) bool {
	if strings.HasSuffix(name, ".star") {
		return false
	}
	return validStoreName(name)
}
