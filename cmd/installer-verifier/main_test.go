package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeTrustVerifier struct {
	packageCalls   int
	payloadCalls   int
	bundleCalls    int
	bundleInput    bundleInput
	installCalls   int
	rollbackCalls  int
	uninstallCalls int
	err            error
}

func (f *fakeTrustVerifier) verifyBundle(input bundleInput) error {
	f.bundleCalls++
	f.bundleInput = input
	return f.err
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
func (f *fakeTrustVerifier) installFirewall() error   { f.installCalls++; return f.err }
func (f *fakeTrustVerifier) rollbackFirewall() error  { f.rollbackCalls++; return f.err }
func (f *fakeTrustVerifier) uninstallFirewall() error { f.uninstallCalls++; return f.err }
func (f *fakeTrustVerifier) cleanupRuntime() error    { return f.err }

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

func TestRunRoutesFirewallInstallRollbackAndUninstallSeparately(t *testing.T) {
	tests := []struct {
		command string
		want    [3]int
	}{
		{command: "firewall-install", want: [3]int{1, 0, 0}},
		{command: "firewall-rollback", want: [3]int{0, 1, 0}},
		{command: "firewall-uninstall", want: [3]int{0, 0, 1}},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			fake := &fakeTrustVerifier{}
			if got := run([]string{test.command}, fake, io.Discard); got != 0 {
				t.Fatalf("run exit = %d", got)
			}
			got := [3]int{fake.installCalls, fake.rollbackCalls, fake.uninstallCalls}
			if got != test.want {
				t.Fatalf("firewall calls = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRunVerifyBundleRequiresExactPinnedContract(t *testing.T) {
	valid := []string{
		"verify-bundle",
		"--bundle", `C:\Staging\client-bundle`,
		"--msi", `C:\Staging\client.msi`,
		"--fixture-manifest", `C:\Staging\fixture-manifest.json`,
		"--fixture-signature", `C:\Staging\fixture-manifest.json.p7s`,
		"--release-manifest", `C:\Staging\client-bundle\artifact-manifest.json`,
		"--release-signature", `C:\Staging\client-bundle\artifact-manifest.json.p7s`,
		"--expected-commit", strings.Repeat("a", 40),
		"--expected-msi-sha256", strings.Repeat("b", 64),
		"--expected-fixture-sha256", strings.Repeat("c", 64),
		"--expected-release-sha256", strings.Repeat("d", 64),
		"--fixture-signer", strings.Repeat("E", 40),
		"--release-signer", strings.Repeat("F", 40),
		"--msi-signer", strings.Repeat("1", 40),
		"--evidence", `D:\Evidence\installer-verifier.json`,
	}
	fake := &fakeTrustVerifier{}
	if got := run(valid, fake, io.Discard); got != 0 || fake.bundleCalls != 1 {
		t.Fatalf("valid verify-bundle exit=%d calls=%d", got, fake.bundleCalls)
	}
	if fake.bundleInput.ReleaseManifest != valid[10] || fake.bundleInput.ExpectedCommit != valid[14] || fake.bundleInput.Evidence != valid[28] {
		t.Fatalf("bundle input=%#v", fake.bundleInput)
	}
	for index := 1; index < len(valid); index++ {
		args := append([]string(nil), valid...)
		args = append(args[:index], args[index+1:]...)
		fake := &fakeTrustVerifier{}
		if got := run(args, fake, io.Discard); got == 0 || fake.bundleCalls != 0 {
			t.Fatalf("missing argument %d: exit=%d calls=%d", index, got, fake.bundleCalls)
		}
	}
	for index, replacement := range map[int]string{14: "not-a-commit", 16: "bad", 18: "bad", 20: "bad", 22: "bad", 24: "bad", 26: "bad"} {
		args := append([]string(nil), valid...)
		args[index] = replacement
		fake := &fakeTrustVerifier{}
		if got := run(args, fake, io.Discard); got == 0 || fake.bundleCalls != 0 {
			t.Fatalf("invalid argument %d: exit=%d calls=%d", index, got, fake.bundleCalls)
		}
	}
}

func TestInvalidInvocationExitCodeIdentifiesPayloadShapeWithoutValues(t *testing.T) {
	if got := invalidInvocationExitCode([]string{"payload"}); got != 21 {
		t.Fatalf("one-argument payload diagnostic = %d, want 21", got)
	}
	args := []string{"payload", "--wrong", "x", "--program-data", "x", "--manifest", "x", "--signature", "x", "--thumbprint", strings.Repeat("A", 40)}
	if got := invalidInvocationExitCode(args); got != 41 {
		t.Fatalf("first payload flag diagnostic = %d, want 41", got)
	}
}
