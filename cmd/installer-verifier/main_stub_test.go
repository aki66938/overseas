//go:build !windows

package main

import (
	"strings"
	"testing"
)

func TestUnsupportedBundleVerificationFailsClosed(t *testing.T) {
	err := (unsupportedTrustVerifier{}).verifyBundle(bundleInput{})
	if err == nil || !strings.Contains(err.Error(), "Windows-only") {
		t.Fatalf("verifyBundle must reject unavailable capability: %v", err)
	}
}
