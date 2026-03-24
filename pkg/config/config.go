package config

import (
	_ "embed"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/samber/oops"
)

//go:embed default.toml
var defaultTOML string

type Config struct {
	Env  map[string]string    `toml:"env"`
	Rule map[string]Rule      `toml:"rule"`
	CLI  map[string]CLIConfig `toml:"cli"`
}

type Rule struct {
	Script      string           `toml:"script"`
	ExtraMounts []ExtraMountSpec `toml:"extra_mounts"`
}

type ExtraMountSpec struct {
	Source   string `toml:"source"`
	Target   string `toml:"target"`
	ReadOnly bool   `toml:"readonly"`
}

type CLIConfig struct {
	Mounts []MountSpec       `toml:"mounts"`
	Env    map[string]string `toml:"env"`
	Rules  []string          `toml:"rules"`
}

type MountSpec struct {
	Name   string `toml:"name"`
	Target string `toml:"target"`
	File   bool   `toml:"file"`
}

// Validate checks that all rule references in CLI configs point to defined rules.
func (c *Config) Validate() error {
	for cliName, cli := range c.CLI {
		for _, ruleName := range cli.Rules {
			if _, ok := c.Rule[ruleName]; !ok {
				return oops.In("config").Errorf("cli %q references undefined rule %q", cliName, ruleName)
			}
		}
	}
	return nil
}

// ResolveScriptPath returns the absolute path for a rule's script,
// resolved relative to configDir. Returns empty string if the rule has no script.
func (r *Rule) ResolveScriptPath(configDir string) string {
	if r.Script == "" {
		return ""
	}
	if filepath.IsAbs(r.Script) {
		return r.Script
	}
	return filepath.Join(configDir, r.Script)
}

// Load parses a TOML config from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, oops.In("config").Wrapf(err, "read config")
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, oops.In("config").Wrapf(err, "parse config")
	}
	return &cfg, nil
}

// LoadDefault parses the embedded default config.
func LoadDefault() (*Config, error) {
	var cfg Config
	if err := toml.Unmarshal([]byte(defaultTOML), &cfg); err != nil {
		return nil, oops.In("config").Wrapf(err, "parse default config")
	}
	return &cfg, nil
}

// DefaultTOML returns the embedded default config as a string.
func DefaultTOML() string {
	return defaultTOML
}
