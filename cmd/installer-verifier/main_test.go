package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeTrustVerifier struct {
	packageCalls int
	payloadCalls int
	err          error
}

func (f *fakeTrustVerifier) verifyPackage(msi, thumbprint string) error {
	f.packageCalls++
	if msi == "" || thumbprint == "" {
		return errors.New("missing package input")
	}
	return f.err
}

func (f *fakeTrustVerifier) verifyPayload(input payloadInput) error {
	f.payloadCalls++
	if input.ProgramFiles == "" || input.ProgramData == "" || input.Manifest == "" || input.Signature == "" || input.Thumbprint == "" {
		return errors.New("missing payload input")
	}
	return f.err
}
func (f *fakeTrustVerifier) installFirewall() error { return f.err }
func (f *fakeTrustVerifier) removeFirewall() error  { return f.err }
func (f *fakeTrustVerifier) cleanupRuntime() error  { return f.err }

func TestRunPackageRequiresExactArgumentsAndPropagatesTrustFailure(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"package"},
		{"package", "--msi", "x.msi"},
		{"package", "--msi", "x.msi", "--thumbprint", strings.Repeat("0", 40), "extra"},
		{"package", "--msi", "x.msi", "--thumbprint", "not-sha1"},
	} {
		fake := &fakeTrustVerifier{}
		if got := run(args, fake, io.Discard); got == 0 {
			t.Fatalf("run(%q) succeeded", args)
		}
		if fake.packageCalls != 0 {
			t.Fatalf("run(%q) invoked verifier before argument validation", args)
		}
	}

	fake := &fakeTrustVerifier{err: errors.New("wrong signer: sensitive detail")}
	var output strings.Builder
	got := run([]string{"package", "--msi", `C:\staged\setup.msi`, "--thumbprint", strings.Repeat("A", 40)}, fake, &output)
	if got == 0 || fake.packageCalls != 1 {
		t.Fatalf("run exit=%d calls=%d", got, fake.packageCalls)
	}
	if strings.Contains(output.String(), "sensitive") || output.String() != "installer trust verification failed\n" {
		t.Fatalf("unsafe output %q", output.String())
	}
}

func TestRunPayloadRequiresEveryFixedInput(t *testing.T) {
	valid := []string{"payload", "--program-files", `C:\Program Files\RegenBio\OverseasAccess`, "--program-data", `C:\ProgramData\RegenBio\OverseasAccess`, "--manifest", `C:\ProgramData\RegenBio\OverseasAccess\artifact-manifest.json`, "--signature", `C:\ProgramData\RegenBio\OverseasAccess\artifact-manifest.json.p7s`, "--thumbprint", strings.Repeat("B", 40)}
	fake := &fakeTrustVerifier{}
	if got := run(valid, fake, io.Discard); got != 0 || fake.payloadCalls != 1 {
		t.Fatalf("valid payload exit=%d calls=%d", got, fake.payloadCalls)
	}
	for index := 1; index < len(valid); index++ {
		args := append([]string(nil), valid...)
		args = append(args[:index], args[index+1:]...)
		fake := &fakeTrustVerifier{}
		if got := run(args, fake, io.Discard); got == 0 || fake.payloadCalls != 0 {
			t.Fatalf("missing argument %d: exit=%d calls=%d", index, got, fake.payloadCalls)
		}
	}
}
