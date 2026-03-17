package config

import (
	_ "embed"
	"os"

	"github.com/BurntSushi/toml"
)

//go:embed default.toml
var defaultTOML string

type Config struct {
	Env map[string]string    `toml:"env"`
	CLI map[string]CLIConfig `toml:"cli"`
}

type CLIConfig struct {
	Mounts []MountSpec       `toml:"mounts"`
	Env    map[string]string `toml:"env"`
}

type MountSpec struct {
	Source string `toml:"source"`
	Target string `toml:"target"`
}

// Load parses a TOML config from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadDefault parses the embedded default config.
func LoadDefault() (*Config, error) {
	var cfg Config
	if err := toml.Unmarshal([]byte(defaultTOML), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// DefaultTOML returns the embedded default config as a string.
func DefaultTOML() string {
	return defaultTOML
}
