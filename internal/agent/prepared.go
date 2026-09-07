package agent

import (
	"errors"
	"regexp"
)

var lowercaseSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Typed boundary errors let the controller report tun_not_found only when the
// deadline truly expired without the adapter, tun_identity_mismatch when a
// candidate adapter exists but fails ownership validation, and distinguish
// runtime monitor causes without recasting them as TUN errors.
// Platform adapters may wrap these exported sentinels with %w; the controller
// recognizes them with errors.Is without depending on OS-specific error text.
var (
	ErrTUNNotFound         = errors.New("fixed TUN adapter did not appear before the deadline")
	ErrTUNIdentityMismatch = errors.New("fixed TUN adapter identity does not match the owned definition")
	ErrNetworkChanged      = errors.New("network fingerprint changed while connected")
	ErrVPNConflict         = errors.New("a foreign VPN tunnel adapter is active")
	ErrFirewallAudit       = errors.New("prepared firewall audit failed")
)

type PreparedNetwork struct {
	Generation   uint64 `json:"generation"`
	Fingerprint  string `json:"fingerprint"`
	AdapterCount int    `json:"adapter_count"`
	RuleCount    int    `json:"rule_count"`
}

func validatePreparedNetwork(prepared PreparedNetwork) error {
	if prepared.Generation == 0 {
		return errors.New("prepared generation is required")
	}
	if !lowercaseSHA256Pattern.MatchString(prepared.Fingerprint) {
		return errors.New("prepared fingerprint must be lowercase SHA-256")
	}
	if prepared.AdapterCount <= 0 {
		return errors.New("prepared adapter count must be positive")
	}
	// RuleCount may be zero in the PoC fast path: no firewall pool.
	return nil
}

// Internal aliases preserve the existing controller classification contract.
var (
	errTUNNotFound         = ErrTUNNotFound
	errTUNIdentityMismatch = ErrTUNIdentityMismatch
	errNetworkChanged      = ErrNetworkChanged
	errVPNConflict         = ErrVPNConflict
	errFirewallAudit       = ErrFirewallAudit
)
