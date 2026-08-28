package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestRunValidatePolicyExitCodes(t *testing.T) {
	validPath := writePolicyFile(t, validPolicyYAML)
	invalidPath := writePolicyFile(t, invalidPolicyYAML)

	tests := []struct {
		name     string
		args     []string
		stdin    string
		wantCode int
	}{
		{name: "valid", args: []string{"validate-policy", "-in", validPath}, wantCode: 0},
		{name: "usage", args: []string{"validate-policy"}, wantCode: 2},
		{name: "invalid", args: []string{"validate-policy", "-in", invalidPath}, wantCode: 3},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(test.args, bytes.NewBufferString(test.stdin), &stdout, &stderr)
			if code != test.wantCode {
				t.Fatalf("run(%q) exit = %d, stdout = %q, stderr = %q", test.args, code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunValidatePolicyRejectsUnknownYAMLField(t *testing.T) {
	path := writePolicyFile(t, validPolicyYAML+"unexpected: true\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"validate-policy", "-in", path}, bytes.NewBuffer(nil), &stdout, &stderr)
	if code != 3 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no output", stdout.String())
	}
	if matched := regexp.MustCompile(`unexpected`).MatchString(stderr.String()); !matched {
		t.Fatalf("stderr = %q, want unknown field detail", stderr.String())
	}
}

func TestRunHashPolicyPrintsLowercaseSHA256(t *testing.T) {
	path := writePolicyFile(t, validPolicyYAML)

	var stdout, stderr bytes.Buffer
	code := run([]string{"hash-policy", "-in", path}, bytes.NewBuffer(nil), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want no error output", stderr.String())
	}
	if matched := regexp.MustCompile(`^[0-9a-f]{64}\n$`).Match(stdout.Bytes()); !matched {
		t.Fatalf("stdout = %q, want lowercase SHA-256 and newline", stdout.String())
	}
}

func writePolicyFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access-poc.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

const validPolicyYAML = `schema_version: 1
mode: poc
nodes:
  - id: vm101
    address: 172.20.9.15
    port: 18443
    priority: 10
corporate_cidrs:
  - 172.20.8.0/22
corporate_dns:
  - 172.20.10.1
internal_suffixes:
  - ad.intra.regen-bio.com
block_udp: true
block_quic: true
credential:
  kind: dpapi-file
  path: C:\ProgramData\RegenBio\OverseasAccess\credential.bin
`

const invalidPolicyYAML = `schema_version: 1
mode: poc
nodes:
  - id: vm101
    address: 172.20.9.15
    port: 18443
corporate_cidrs:
  - 0.0.0.0/0
block_udp: true
block_quic: true
credential:
  kind: dpapi-file
  path: C:\ProgramData\RegenBio\OverseasAccess\credential.bin
`
