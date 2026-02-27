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
