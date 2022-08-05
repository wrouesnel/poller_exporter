package config

import (
	"io/ioutil"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

func Load(s string) (*Config, error) {
	cfg := new(Config)
	*cfg = DefaultConfig

	// Important: we treat the yaml file as a big list, and unmarshal to our
	// big list here.
	err := yaml.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, errors.Wrap(err, "Load config failed")
	}
	cfg.OriginalConfig = s
	return cfg, nil
}

func LoadFromFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "LoadFromFile failed: %s", filename)
	}
	return Load(string(content))
}

func Save(cfg *Config) ([]byte, error) {
	out, err := yaml.Marshal(cfg)
	return out, errors.Wrap(err, "Config.Save failed")
}
