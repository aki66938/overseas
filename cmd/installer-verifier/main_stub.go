//go:build !windows

package main

import (
	"errors"
	"os"
)

type unsupportedTrustVerifier struct{}

func (unsupportedTrustVerifier) ensureSharedRoot() error { return errors.New("unsupported") }

func main() { os.Exit(run(os.Args[1:], unsupportedTrustVerifier{}, os.Stderr)) }

func (unsupportedTrustVerifier) verifyPackage(_, _ string) error {
	return errors.New("installer verification is Windows-only")
}

func (unsupportedTrustVerifier) verifyPayload(payloadInput) error {
	return errors.New("installer verification is Windows-only")
}
func (unsupportedTrustVerifier) verifyBundle(bundleInput) error {
	return errors.New("installer verification is Windows-only")
}
func (unsupportedTrustVerifier) installFirewall() error       { return errors.New("unsupported") }
func (unsupportedTrustVerifier) rollbackFirewall() error      { return errors.New("unsupported") }
func (unsupportedTrustVerifier) uninstallFirewall() error     { return errors.New("unsupported") }
func (unsupportedTrustVerifier) cleanupRuntime() error        { return errors.New("unsupported") }
func (unsupportedTrustVerifier) prepareUpgrade() error        { return errors.New("unsupported") }
func (unsupportedTrustVerifier) snapshotUpgrade(string) error { return errors.New("unsupported") }
