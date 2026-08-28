//go:build !windows

package main

import (
	"errors"
	"os"
)

type unsupportedTrustVerifier struct{}

func main() { os.Exit(run(os.Args[1:], unsupportedTrustVerifier{}, os.Stderr)) }

func (unsupportedTrustVerifier) verifyPackage(_, _ string) error {
	return errors.New("installer verification is Windows-only")
}

func (unsupportedTrustVerifier) verifyPayload(payloadInput) error {
	return errors.New("installer verification is Windows-only")
}
func (unsupportedTrustVerifier) installFirewall() error { return errors.New("unsupported") }
func (unsupportedTrustVerifier) removeFirewall() error  { return errors.New("unsupported") }
func (unsupportedTrustVerifier) cleanupRuntime() error  { return errors.New("unsupported") }
