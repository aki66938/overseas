package main

import (
	"fmt"
	"io"
	"regexp"
)

var sha1Thumbprint = regexp.MustCompile(`^[A-Fa-f0-9]{40}$`)

type payloadInput struct {
	ProgramFiles string
	ProgramData  string
	Manifest     string
	Signature    string
	Thumbprint   string
}

type trustVerifier interface {
	verifyPackage(msi, thumbprint string) error
	verifyPayload(payloadInput) error
	installFirewall() error
	removeFirewall() error
	cleanupRuntime() error
}

func run(args []string, verifier trustVerifier, errorOutput io.Writer) int {
	switch {
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
	case len(args) == 1 && args[0] == "firewall-remove":
		if err := verifier.removeFirewall(); err != nil {
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
		return 2
	}
}
