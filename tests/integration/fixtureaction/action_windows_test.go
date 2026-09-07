//go:build windows

package main

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProvisionerPlanUsesInstalledManifestPinnedExecutableAndPipeOnlyInput(t *testing.T) {
	payload := testPayloadManifest()
	config := runtimeConfig{CredentialSourcePath: `C:\fixture\credential-source.exe`, CredentialSourceSHA256: strings.Repeat("f", 64), CredentialExpiresAt: "2099-01-01T00:00:00Z"}
	client := []byte(`{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"shadowsocks","tag":"tunnel","server":"172.20.9.15","server_port":18443,"method":"2022-blake3-aes-128-gcm"}],"route":{"final":"tunnel"}}`)
	plan, err := provisionerPlan(config, client, payload, time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if plan.ProvisionerPath != `C:\Program Files\RegenBio\OverseasAccess\credential-provisioner.exe` || plan.SourcePath != config.CredentialSourcePath {
		t.Fatalf("plan=%#v", plan)
	}
	wantArgs := []string{"--expected-method", "2022-blake3-aes-128-gcm", "--expected-endpoint", "172.20.9.15:18443", "--expected-expires-at", "2099-01-01T00:00:00Z"}
	if !reflect.DeepEqual(plan.SourceArgs, wantArgs) || !reflect.DeepEqual(plan.ProvisionerArgs, wantArgs) {
		t.Fatalf("plan args=%#v/%#v", plan.SourceArgs, plan.ProvisionerArgs)
	}
	config.CredentialExpiresAt = "2026-08-30T00:00:00Z"
	if _, err := provisionerPlan(config, client, payload, time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "expiration") {
		t.Fatalf("expired contract accepted: %v", err)
	}
}

func TestInstallerArgumentsAreFixedByTypedOperation(t *testing.T) {
	config := runtimeConfig{PowerShellPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, InstallerScriptPath: `C:\fixture\install-client.ps1`, BundlePath: `C:\fixture\bundle`, PayloadManifestPath: `C:\fixture\payload.json`}
	tests := []struct {
		operation, mode string
		want            []string
	}{
		{operation: "install", mode: "Install", want: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", config.InstallerScriptPath, "-Mode", "Install", "-BundlePath", config.BundlePath, "-PayloadManifestPath", config.PayloadManifestPath}},
		{operation: "repair", mode: "Repair", want: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", config.InstallerScriptPath, "-Mode", "Repair", "-BundlePath", config.BundlePath, "-PayloadManifestPath", config.PayloadManifestPath}},
		{operation: "uninstall", mode: "Uninstall", want: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-File", config.InstallerScriptPath, "-Mode", "Uninstall", "-Confirm:$false"}},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			executable, args, err := installerCommand(config, test.operation)
			if err != nil {
				t.Fatal(err)
			}
			if executable != config.PowerShellPath || !reflect.DeepEqual(args, test.want) {
				t.Fatalf("installerCommand() = %q %#v, want %#v", executable, args, test.want)
			}
		})
	}
	if _, _, err := installerCommand(config, "free-form"); err == nil {
		t.Fatal("installerCommand accepted free-form operation")
	}
}
