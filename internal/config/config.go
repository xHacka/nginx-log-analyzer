package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogPath      string `yaml:"log_path"`
	DBPath       string `yaml:"db_path"`
	RetentionDays int   `yaml:"retention_days"`
	Listen       string `yaml:"listen"`
	Ignore       IgnoreConfig `yaml:"ignore"`
}

type IgnoreConfig struct {
	WhitelistedIPs []string `yaml:"whitelisted_ips"`
	SkipExtensions []string `yaml:"skip_extensions"`
	SkipMethods    []string `yaml:"skip_methods"`
	SkipStatusCodes []int   `yaml:"skip_status_codes"`
	SkipPathPrefixes []string `yaml:"skip_path_prefixes"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 30
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "./data/access.db"
	}
	return &cfg, nil
}
