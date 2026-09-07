package agent

import (
	"strings"
	"testing"
)

func TestPreparedNetworkJSONContract(t *testing.T) {
	prepared := PreparedNetwork{Generation: 4, Fingerprint: strings.Repeat("a", 64), AdapterCount: 7, RuleCount: 10}
	if err := validatePreparedNetwork(prepared); err != nil {
		t.Fatalf("validatePreparedNetwork() error = %v", err)
	}
	for _, invalid := range []PreparedNetwork{
		{},
		{Generation: 1, Fingerprint: "ABC", AdapterCount: 1, RuleCount: 4},
		{Generation: 1, Fingerprint: strings.Repeat("a", 64), AdapterCount: 0, RuleCount: 3},
	} {
		if err := validatePreparedNetwork(invalid); err == nil {
			t.Fatalf("validatePreparedNetwork(%+v) succeeded", invalid)
		}
	}
	// RuleCount 0 is valid in the PoC fast path (no firewall pool).
	if err := validatePreparedNetwork(PreparedNetwork{Generation: 1, Fingerprint: strings.Repeat("a", 64), AdapterCount: 1, RuleCount: 0}); err != nil {
		t.Fatalf("validatePreparedNetwork(poc zero-rule) = %v", err)
	}
}
