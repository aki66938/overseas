package accessmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
)

const (
	schemaVersion = 1
	modePoC       = "poc"
)

func Validate(policy Policy) error {
	if policy.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema_version must be %d", schemaVersion)
	}
	if policy.Mode != modePoC {
		return fmt.Errorf("mode must be %q", modePoC)
	}
	if !policy.BlockUDP {
		return fmt.Errorf("block_udp must be true")
	}
	if !policy.BlockQUIC {
		return fmt.Errorf("block_quic must be true")
	}
	if err := validateCredential(policy.Credential); err != nil {
		return err
	}
	if err := validateNodes(policy.Nodes); err != nil {
		return err
	}
	if err := validateCorporateCIDRs(policy.CorporateCIDRs); err != nil {
		return err
	}
	if err := validateCorporateDNS(policy.CorporateDNS); err != nil {
		return err
	}
	if err := validateInternalSuffixes(policy.InternalSuffixes); err != nil {
		return err
	}
	return nil
}

func validateCredential(credential CredentialRef) error {
	if credential.Kind != "dpapi-file" {
		return fmt.Errorf("credential.kind must be %q", "dpapi-file")
	}
	if !filepath.IsAbs(credential.Path) {
		return fmt.Errorf("credential.path must be an absolute path")
	}
	return nil
}

func validateNodes(nodes []Node) error {
	if len(nodes) == 0 {
		return fmt.Errorf("nodes must not be empty")
	}
	seenIDs := make(map[string]struct{}, len(nodes))
	seenEndpoints := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if strings.TrimSpace(node.ID) == "" {
			return fmt.Errorf("nodes.id must not be empty")
		}
		if _, exists := seenIDs[node.ID]; exists {
			return fmt.Errorf("nodes.id must be unique")
		}
		seenIDs[node.ID] = struct{}{}

		addr, err := netip.ParseAddr(node.Address)
		if err != nil {
			return fmt.Errorf("nodes.address must contain valid IP addresses")
		}
		if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("nodes.address must not contain loopback, multicast, or unspecified addresses")
		}
		if node.Port < 1024 {
			return fmt.Errorf("nodes.port must be 1024 or higher")
		}

		endpoint := addr.String() + ":" + fmt.Sprintf("%d", node.Port)
		if _, exists := seenEndpoints[endpoint]; exists {
			return fmt.Errorf("nodes endpoint must be unique")
		}
		seenEndpoints[endpoint] = struct{}{}
	}
	return nil
}

func validateCorporateCIDRs(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("corporate_cidrs must not be empty")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value {
			return fmt.Errorf("corporate_cidrs must contain canonical CIDRs")
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("corporate_cidrs must not include a default route")
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("corporate_cidrs must not contain duplicates")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateCorporateDNS(values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return fmt.Errorf("corporate_dns must contain valid IP addresses")
		}
		if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("corporate_dns must not contain loopback, multicast, or unspecified addresses")
		}
		canonical := addr.String()
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("corporate_dns must not contain duplicates")
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

func validateInternalSuffixes(values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("internal_suffixes must not contain empty values")
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("internal_suffixes must not contain duplicates")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func CanonicalSHA256(policy Policy) (string, error) {
	if err := Validate(policy); err != nil {
		return "", err
	}

	canonical := Policy{
		SchemaVersion:    policy.SchemaVersion,
		Mode:             policy.Mode,
		Nodes:            append([]Node(nil), policy.Nodes...),
		CorporateCIDRs:   append([]string(nil), policy.CorporateCIDRs...),
		CorporateDNS:     append([]string(nil), policy.CorporateDNS...),
		InternalSuffixes: append([]string(nil), policy.InternalSuffixes...),
		BlockUDP:         policy.BlockUDP,
		BlockQUIC:        policy.BlockQUIC,
		Credential:       policy.Credential,
	}

	sort.Slice(canonical.Nodes, func(i, j int) bool {
		left := canonical.Nodes[i]
		right := canonical.Nodes[j]
		switch {
		case left.ID != right.ID:
			return left.ID < right.ID
		case left.Address != right.Address:
			return left.Address < right.Address
		case left.Port != right.Port:
			return left.Port < right.Port
		default:
			return left.Priority < right.Priority
		}
	})
	sort.Strings(canonical.CorporateCIDRs)
	sort.Strings(canonical.CorporateDNS)
	sort.Strings(canonical.InternalSuffixes)

	contents, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode canonical policy: %w", err)
	}
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:]), nil
}
