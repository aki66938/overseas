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

func TestRunRenderServerWritesConfigAndAclHint(t *testing.T) {
	policyPath := writePolicyFile(t, validPolicyYAML)
	outputPath := filepath.Join(t.TempDir(), "server.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"render-server",
			"-in", policyPath,
			"-node", "vm101",
			"-listen", "0.0.0.0",
			"-upstream", "127.0.0.1:8080",
			"-out", outputPath,
			"-secret-stdin",
		},
		bytes.NewBufferString("MDEyMzQ1Njc4OWFiY2RlZg==\n"),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want no error output", stderr.String())
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if matched := regexp.MustCompile(`"final":"telecom"`).Match(contents); !matched {
		t.Fatalf("rendered config = %q, want telecom route final", string(contents))
	}
	if matched := regexp.MustCompile(`CONFIG_WRITTEN`).Match(stdout.Bytes()); !matched {
		t.Fatalf("stdout = %q, want config write confirmation", stdout.String())
	}
	if matched := regexp.MustCompile(`APPLY_SERVICE_ONLY_ACL`).Match(stdout.Bytes()); !matched {
		t.Fatalf("stdout = %q, want ACL hint", stdout.String())
	}
}

func TestRunRenderClientWritesConfigAndAclHint(t *testing.T) {
	policyPath := writePolicyFile(t, validPolicyYAML)
	outputPath := filepath.Join(t.TempDir(), "client.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"render-client",
			"-in", policyPath,
			"-node", "vm101",
			"-out", outputPath,
			"-secret-stdin",
		},
		bytes.NewBufferString("MDEyMzQ1Njc4OWFiY2RlZg==\n"),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want no error output", stderr.String())
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if matched := regexp.MustCompile(`"final":"tunnel"`).Match(contents); !matched {
		t.Fatalf("rendered config = %q, want tunnel route final", string(contents))
	}
	if matched := regexp.MustCompile(`CONFIG_WRITTEN`).Match(stdout.Bytes()); !matched {
		t.Fatalf("stdout = %q, want config write confirmation", stdout.String())
	}
	if matched := regexp.MustCompile(`APPLY_SERVICE_ONLY_ACL`).Match(stdout.Bytes()); !matched {
		t.Fatalf("stdout = %q, want ACL hint", stdout.String())
	}
}

func TestRunRenderCommandsRequireDedicatedSecretSource(t *testing.T) {
	policyPath := writePolicyFile(t, validPolicyYAML)
	outputPath := filepath.Join(t.TempDir(), "client.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"render-client",
			"-in", policyPath,
			"-node", "vm101",
			"-out", outputPath,
		},
		bytes.NewBuffer(nil),
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if matched := regexp.MustCompile(`USAGE`).Match(stderr.Bytes()); !matched {
		t.Fatalf("stderr = %q, want usage guidance", stderr.String())
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
