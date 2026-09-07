package main

import (
	"fmt"
	"io"
	"regexp"
)

var sha1Thumbprint = regexp.MustCompile(`^[A-Fa-f0-9]{40}$`)
var sha256Digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var sourceCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)

type payloadInput struct {
	ProgramFiles string
	ProgramData  string
	Manifest     string
	Signature    string
	Thumbprint   string
}

type bundleInput struct {
	Bundle, MSI, FixtureManifest, FixtureSignature, ReleaseManifest, ReleaseSignature string
	ExpectedCommit, ExpectedMSISHA256, ExpectedFixtureSHA256, ExpectedReleaseSHA256   string
	FixtureSigner, ReleaseSigner, MSISigner, Evidence                                 string
}

type trustVerifier interface {
	verifyBundle(bundleInput) error
	verifyPackage(msi, thumbprint string) error
	verifyPayload(payloadInput) error
	installFirewall() error
	rollbackFirewall() error
	uninstallFirewall() error
	cleanupRuntime() error
	prepareUpgrade() error
}

func run(args []string, verifier trustVerifier, errorOutput io.Writer) int {
	switch {
	case len(args) == 1 && args[0] == "prepare-upgrade":
		if err := verifier.prepareUpgrade(); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "upgrade restoration could not be proven")
			return 1
		}
		return 0
	case validBundleArguments(args):
		input := bundleInput{
			Bundle: args[2], MSI: args[4], FixtureManifest: args[6], FixtureSignature: args[8],
			ReleaseManifest: args[10], ReleaseSignature: args[12], ExpectedCommit: args[14],
			ExpectedMSISHA256: args[16], ExpectedFixtureSHA256: args[18], ExpectedReleaseSHA256: args[20],
			FixtureSigner: args[22], ReleaseSigner: args[24], MSISigner: args[26], Evidence: args[28],
		}
		if err := verifier.verifyBundle(input); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "pre-install bundle verification failed")
			return 1
		}
		return 0
	case len(args) == 5 && args[0] == "package" && args[1] == "--msi" && args[3] == "--thumbprint" && sha1Thumbprint.MatchString(args[4]):
		if err := verifier.verifyPackage(args[2], args[4]); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "installer trust verification failed")
			return 1
		}
		return 0
	case len(args) == 11 && args[0] == "payload" && args[1] == "--program-files" && args[3] == "--program-data" && args[5] == "--manifest" && args[7] == "--signature" && args[9] == "--thumbprint" && sha1Thumbprint.MatchString(args[10]):
		input := payloadInput{ProgramFiles: args[2], ProgramData: args[4], Manifest: args[6], Signature: args[8], Thumbprint: args[10]}
		if err := verifier.verifyPayload(input); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "installed payload verification failed")
			return 1
		}
		return 0
	case len(args) == 1 && args[0] == "firewall-install":
		if err := verifier.installFirewall(); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "installer firewall operation failed")
			return 1
		}
		return 0
	case len(args) == 1 && args[0] == "firewall-rollback":
		if err := verifier.rollbackFirewall(); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "installer firewall operation failed")
			return 1
		}
		return 0
	case len(args) == 1 && args[0] == "firewall-uninstall":
		if err := verifier.uninstallFirewall(); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "installer firewall operation failed")
			return 1
		}
		return 0
	case len(args) == 1 && args[0] == "runtime-cleanup":
		if err := verifier.cleanupRuntime(); err != nil {
			_, _ = fmt.Fprintln(errorOutput, "runtime cleanup failed")
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprintln(errorOutput, "installer trust verification failed")
		return invalidInvocationExitCode(args)
	}
}

func invalidInvocationExitCode(args []string) int {
	if len(args) > 0 && args[0] == "payload" {
		if len(args) != 11 {
			if len(args) > 19 {
				return 39
			}
			return 20 + len(args)
		}
		expected := map[int]string{1: "--program-files", 3: "--program-data", 5: "--manifest", 7: "--signature", 9: "--thumbprint"}
		for _, index := range []int{1, 3, 5, 7, 9} {
			if args[index] != expected[index] {
				return 40 + index
			}
		}
		if !sha1Thumbprint.MatchString(args[10]) {
			return 70
		}
	}
	return 2
}

func validBundleArguments(args []string) bool {
	if len(args) != 29 || args[0] != "verify-bundle" {
		return false
	}
	flags := []string{"--bundle", "--msi", "--fixture-manifest", "--fixture-signature", "--release-manifest", "--release-signature", "--expected-commit", "--expected-msi-sha256", "--expected-fixture-sha256", "--expected-release-sha256", "--fixture-signer", "--release-signer", "--msi-signer", "--evidence"}
	for index, flag := range flags {
		if args[1+index*2] != flag || args[2+index*2] == "" {
			return false
		}
	}
	return sourceCommit.MatchString(args[14]) && sha256Digest.MatchString(args[16]) && sha256Digest.MatchString(args[18]) && sha256Digest.MatchString(args[20]) && sha1Thumbprint.MatchString(args[22]) && sha1Thumbprint.MatchString(args[24]) && sha1Thumbprint.MatchString(args[26])
}
