package config

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WireGuardSubnet    string        `yaml:"wireguard_subnet"`
	WireGuardInterface string        `yaml:"wireguard_interface"`
	TelecomInterface   string        `yaml:"telecom_interface"`
	EmployeeInterface  string        `yaml:"employee_interface"`
	InternalCIDRs      []string      `yaml:"internal_cidrs"`
	ApprovedTargets    []Target      `yaml:"approved_targets"`
	ProbeTimeout       time.Duration `yaml:"-"`
	ProbeTimeoutText   string        `yaml:"probe_timeout"`
}

type Target struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

func Load(path string) (Config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, yamlDecodeError(err)
	}
	var additionalDocument any
	if err := decoder.Decode(&additionalDocument); err != io.EOF {
		return Config{}, fmt.Errorf("configuration must contain exactly one YAML document")
	}

	cfg.ProbeTimeout, err = time.ParseDuration(cfg.ProbeTimeoutText)
	if err != nil {
		return Config{}, fmt.Errorf("probe_timeout must be a valid duration")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func yamlDecodeError(err error) error {
	const fieldMarker = "field "
	const notFoundMarker = " not found"

	message := err.Error()
	start := strings.Index(message, fieldMarker)
	if start >= 0 {
		field := message[start+len(fieldMarker):]
		if end := strings.Index(field, notFoundMarker); end >= 0 {
			return fmt.Errorf("configuration contains unknown field %s", field[:end])
		}
	}

	return fmt.Errorf("configuration YAML is invalid")
}

func (c Config) Validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"wireguard_interface", c.WireGuardInterface},
		{"telecom_interface", c.TelecomInterface},
		{"employee_interface", c.EmployeeInterface},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s must not be empty", field.name)
		}
	}
	if len(c.InternalCIDRs) == 0 {
		return fmt.Errorf("internal_cidrs must not be empty")
	}
	if len(c.ApprovedTargets) == 0 {
		return fmt.Errorf("approved_targets must not be empty")
	}

	wgPrefix, err := netip.ParsePrefix(c.WireGuardSubnet)
	if err != nil {
		return fmt.Errorf("wireguard_subnet must be a valid CIDR")
	}

	for _, cidr := range c.InternalCIDRs {
		internalPrefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("internal_cidrs must contain valid CIDRs")
		}
		if wgPrefix.Overlaps(internalPrefix) {
			return fmt.Errorf("wireguard_subnet must not overlap internal_cidrs")
		}
	}

	targetNames := make(map[string]struct{}, len(c.ApprovedTargets))
	for _, target := range c.ApprovedTargets {
		if strings.TrimSpace(target.Name) == "" {
			return fmt.Errorf("approved_targets names must not be empty")
		}
		parsed, err := url.Parse(target.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("approved_targets must contain HTTPS URLs")
		}
		if _, exists := targetNames[target.Name]; exists {
			return fmt.Errorf("approved_targets must have unique names")
		}
		targetNames[target.Name] = struct{}{}
	}

	if c.ProbeTimeout < time.Second || c.ProbeTimeout > 30*time.Second {
		return fmt.Errorf("probe_timeout must be between 1s and 30s")
	}

	return nil
}
