package agent

import (
	"errors"
	"fmt"
	"testing"
)

func TestAdapterErrorsPreserveControllerClassification(t *testing.T) {
	for _, pair := range [][2]error{
		{ErrTUNNotFound, errTUNNotFound},
		{ErrTUNIdentityMismatch, errTUNIdentityMismatch},
		{ErrNetworkChanged, errNetworkChanged},
		{ErrVPNConflict, errVPNConflict},
		{ErrFirewallAudit, errFirewallAudit},
	} {
		if !errors.Is(fmt.Errorf("adapter context: %w", pair[0]), pair[1]) {
			t.Fatalf("exported adapter error %v lost controller classification", pair[0])
		}
	}
}
