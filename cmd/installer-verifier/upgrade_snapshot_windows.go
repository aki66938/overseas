//go:build windows

package main

import (
	_ "embed"
	"errors"
	"strings"
)

//go:embed upgrade_snapshot.ps1
var upgradeSnapshotScript string

func (windowsTrustVerifier) snapshotUpgrade(mode string) error {
	// Reuse the exact production ownership/semantic validator; do not copy or
	// broaden firewall identity checks for the upgrade snapshot.
	support, _, found := strings.Cut(firewallLifecycleScript, "if($mode -eq 'install'){")
	if !found {
		return errors.New("firewall snapshot support boundary is absent")
	}
	return runPowerShell(support+"\n"+upgradeSnapshotScript, mode)
}
