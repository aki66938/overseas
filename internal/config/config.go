package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	WireGuardSubnet      string        `yaml:"wireguard_subnet"`
	WireGuardInterface   string        `yaml:"wireguard_interface"`
	TelecomInterface     string        `yaml:"telecom_interface"`
	TelecomRoutePrefixes []string      `yaml:"telecom_route_prefixes"`
	EmployeeInterface    string        `yaml:"employee_interface"`
	InternalCIDRs        []string      `yaml:"internal_cidrs"`
	ApprovedTargets      []Target      `yaml:"approved_targets"`
	ProbeTimeout         time.Duration `yaml:"-"`
	ProbeTimeoutText     string        `yaml:"probe_timeout"`
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
	if len(c.TelecomRoutePrefixes) == 0 {
		return fmt.Errorf("telecom_route_prefixes must not be empty")
	}
	if len(c.ApprovedTargets) == 0 {
		return fmt.Errorf("approved_targets must not be empty")
	}

	wgPrefix, err := netip.ParsePrefix(c.WireGuardSubnet)
	if err != nil {
		return fmt.Errorf("wireguard_subnet must be a valid CIDR")
	}

	telecomPrefixes := make(map[string]struct{}, len(c.TelecomRoutePrefixes))
	for _, value := range c.TelecomRoutePrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix.String() != value {
			return fmt.Errorf("telecom_route_prefixes must contain canonical IPv4 CIDRs")
		}
		address := prefix.Addr()
		if prefix.Bits() > 1 && (!address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified()) {
			return fmt.Errorf("telecom_route_prefixes must describe external or default IPv4 routes")
		}
		if _, exists := telecomPrefixes[value]; exists {
			return fmt.Errorf("telecom_route_prefixes must not contain duplicates")
		}
		telecomPrefixes[value] = struct{}{}
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
		if strings.TrimSpace(target.Name) == "" || strings.TrimSpace(target.Name) != target.Name {
			return fmt.Errorf("approved_targets names must be non-empty without surrounding whitespace")
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

// Digest returns a stable SHA-256 binding for the complete validated
// configuration. Slice order is retained because it is part of the exact
// operator-supplied configuration used to produce evidence.
func Digest(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	canonical := struct {
		WireGuardSubnet      string        `json:"wireguard_subnet"`
		WireGuardInterface   string        `json:"wireguard_interface"`
		TelecomInterface     string        `json:"telecom_interface"`
		TelecomRoutePrefixes []string      `json:"telecom_route_prefixes"`
		EmployeeInterface    string        `json:"employee_interface"`
		InternalCIDRs        []string      `json:"internal_cidrs"`
		ApprovedTargets      []Target      `json:"approved_targets"`
		ProbeTimeout         time.Duration `json:"probe_timeout_nanoseconds"`
	}{
		WireGuardSubnet:      c.WireGuardSubnet,
		WireGuardInterface:   c.WireGuardInterface,
		TelecomInterface:     c.TelecomInterface,
		TelecomRoutePrefixes: c.TelecomRoutePrefixes,
		EmployeeInterface:    c.EmployeeInterface,
		InternalCIDRs:        c.InternalCIDRs,
		ApprovedTargets:      c.ApprovedTargets,
		ProbeTimeout:         c.ProbeTimeout,
	}
	contents, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode configuration digest input: %w", err)
	}
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:]), nil
}
