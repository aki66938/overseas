//go:build windows

package main

import _ "embed"

//go:embed shared_root.ps1
var sharedRootScript string

func (windowsTrustVerifier) ensureSharedRoot() error {
	return runPowerShell(safePayloadPathScript + `$null=Resolve-VerifierPayloadPath 'C:\Program Files\RegenBio\OverseasAccess' 'Telecom-GoMITM-Root.cer';` + "\n" + sharedRootScript)
}
