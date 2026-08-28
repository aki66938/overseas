package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func validCredential() []byte {
	return []byte(`{"method":"2022-blake3-aes-128-gcm","password":"never-print-this","expires_at":"2099-01-01T00:00:00Z"}`)
}

func TestRunProvisionerUsesOnlyNonTerminalStdinAndFixedPath(t *testing.T) {
	for _, test := range []struct {
		name     string
		args     []string
		terminal bool
	}{
		{name: "argument", args: []string{"--password", "forbidden"}},
		{name: "terminal", terminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			if got := runProvisioner(test.args, bytes.NewReader(validCredential()), test.terminal, &strings.Builder{}, &strings.Builder{}, func(string, []byte) error { called = true; return nil }); got == 0 || called {
				t.Fatalf("exit=%d storeCalled=%v", got, called)
			}
		})
	}

	var storedPath string
	var stored []byte
	var stdout, stderr strings.Builder
	got := runProvisioner(nil, bytes.NewReader(validCredential()), false, &stdout, &stderr, func(path string, plaintext []byte) error {
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
	invalid := [][]byte{
		{},
		[]byte(`{"method":"x","password":"","expires_at":"2099-01-01T00:00:00Z"}`),
		[]byte(`{"method":"x","password":"secret","expires_at":"2000-01-01T00:00:00Z"}`),
		[]byte(`{"method":"x","password":"secret","expires_at":"2099-01-01T00:00:00Z","extra":true}`),
		[]byte("{}\n{}"),
	}
	for _, input := range invalid {
		original := append([]byte(nil), input...)
		called := false
		err := provisionCredential(input, time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC), func(string, []byte) error { called = true; return nil })
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
	if got := runProvisioner(nil, bytes.NewReader(oversize), false, &strings.Builder{}, &stderr, func(string, []byte) error { return nil }); got == 0 {
		t.Fatal("oversize input succeeded")
	}
	if strings.Contains(stderr.String(), strings.Repeat("x", 20)) {
		t.Fatal("oversize input leaked")
	}

	stderr.Reset()
	if got := runProvisioner(nil, bytes.NewReader(validCredential()), false, &strings.Builder{}, &stderr, func(string, []byte) error { return errors.New("backend included never-print-this") }); got == 0 {
		t.Fatal("store failure succeeded")
	}
	if stderr.String() != "credential provisioning failed\n" {
		t.Fatalf("unsafe error %q", stderr.String())
	}
}
