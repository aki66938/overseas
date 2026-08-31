package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func validCredential() []byte {
	return []byte(`{"method":"2022-blake3-aes-128-gcm","endpoint":"172.20.9.15:18443","password":"never-print-this","expires_at":"2099-01-01T00:00:00Z"}`)
}

func validContractArgs() []string {
	return []string{"--expected-method", "2022-blake3-aes-128-gcm", "--expected-endpoint", "172.20.9.15:18443", "--expected-expires-at", "2099-01-01T00:00:00Z"}
}

func TestRunProvisionerUsesOnlyNonTerminalStdinAndFixedPath(t *testing.T) {
	for _, test := range []struct {
		name     string
		args     []string
		terminal bool
	}{
		{name: "argument", args: []string{"--password", "forbidden"}},
		{name: "missing contract", args: nil},
		{name: "terminal", terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			args := test.args
			if test.terminal {
				args = validContractArgs()
			}
			if got := runProvisioner(args, bytes.NewReader(validCredential()), test.terminal, &strings.Builder{}, &strings.Builder{}, func(string, []byte) error { called = true; return nil }); got == 0 || called {
				t.Fatalf("exit=%d storeCalled=%v", got, called)
			}
		})
	}

	var storedPath string
	var stored []byte
	var stdout, stderr strings.Builder
	got := runProvisioner(validContractArgs(), bytes.NewReader(validCredential()), false, &stdout, &stderr, func(path string, plaintext []byte) error {
		storedPath = path
		stored = append([]byte(nil), plaintext...)
		return nil
	})
	if got != 0 || storedPath != credentialPath || !bytes.Equal(stored, validCredential()) {
		t.Fatalf("exit=%d path=%q stored=%q", got, storedPath, stored)
	}
	if stdout.String() != "credential provisioned\n" || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestProvisionCredentialRejectsInvalidInputAndZeroesCallerBuffer(t *testing.T) {
	contract := credentialContract{Method: "2022-blake3-aes-128-gcm", Endpoint: "172.20.9.15:18443", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}
	invalid := [][]byte{
		{},
		[]byte(`{"method":"2022-blake3-aes-128-gcm","endpoint":"172.20.9.15:18443","password":"","expires_at":"2099-01-01T00:00:00Z"}`),
		[]byte(`{"method":"other","endpoint":"172.20.9.15:18443","password":"secret","expires_at":"2099-01-01T00:00:00Z"}`),
		[]byte(`{"method":"2022-blake3-aes-128-gcm","endpoint":"172.20.9.16:18443","password":"secret","expires_at":"2099-01-01T00:00:00Z"}`),
		[]byte(`{"method":"2022-blake3-aes-128-gcm","endpoint":"172.20.9.15:18443","password":"secret","expires_at":"2099-01-02T00:00:00Z"}`),
		[]byte(`{"method":"2022-blake3-aes-128-gcm","endpoint":"172.20.9.15:18443","password":"secret","expires_at":"2000-01-01T00:00:00Z"}`),
		[]byte(`{"method":"2022-blake3-aes-128-gcm","endpoint":"172.20.9.15:18443","password":"secret","expires_at":"2099-01-01T00:00:00Z","extra":true}`),
		[]byte("{}\n{}"),
	}
	for _, input := range invalid {
		original := append([]byte(nil), input...)
		called := false
		err := provisionCredential(input, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC), contract, func(string, []byte) error { called = true; return nil })
		if err == nil || called {
			t.Fatalf("input %q err=%v called=%v", original, err, called)
		}
		if !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatalf("input buffer not zeroed: %v", input)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("error disclosed input: %v", err)
		}
	}
}

func TestRunProvisionerBoundsInputAndRedactsStoreFailure(t *testing.T) {
	oversize := bytes.Repeat([]byte{'x'}, maxCredentialBytes+1)
	var stderr strings.Builder
	if got := runProvisioner(validContractArgs(), bytes.NewReader(oversize), false, &strings.Builder{}, &stderr, func(string, []byte) error { return nil }); got == 0 {
		t.Fatal("oversize input succeeded")
	}
	if strings.Contains(stderr.String(), strings.Repeat("x", 20)) {
		t.Fatal("oversize input leaked")
	}

	stderr.Reset()
	if got := runProvisioner(validContractArgs(), bytes.NewReader(validCredential()), false, &strings.Builder{}, &stderr, func(string, []byte) error { return errors.New("backend included never-print-this") }); got == 0 {
		t.Fatal("store failure succeeded")
	}
	if stderr.String() != "credential provisioning failed\n" {
		t.Fatalf("unsafe error %q", stderr.String())
	}
}
