//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"corp.example/overseas-access-gateway/tests/integration/fixtureproto"
)

func TestCredentialPipelineUsesConnectedAnonymousPipeAndNoParentSecretChannels(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller path unavailable")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(current), "main_windows.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"os.Pipe()", "provisioner.Stdin = readPipe", "sourceCommand.Stdout = writePipe", "plan.ProvisionerArgs...", "plan.SourceArgs...", `os.Args[1] == "provision-credential"`, "backend.provisionCredential(ctx)"} {
		if !strings.Contains(text, required) {
			t.Fatalf("credential pipeline lacks %q", required)
		}
	}
	for _, forbidden := range []string{"sourceCommand.Stdin,", "sourceCommand.Stdin = os.Stdin", "sourceCommand.Stderr = os.Stderr", "provisioner.Stderr = os.Stderr"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("credential pipeline exposes parent channel %q", forbidden)
		}
	}
}

func TestPhysicalClientActionHelperContainsNoLocalServerLifecycle(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller path unavailable")
	}
	for _, name := range []string{"action.go", "main_windows.go"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(current), name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"productionServerPlan", "setupProductionServer", "removeProductionServer", "verifyProductionServer", "serverOwnerMarker", "RegenBioFixtureServerOwner"} {
			if strings.Contains(string(data), forbidden) {
				t.Fatalf("%s retains dead local-server symbol %q", name, forbidden)
			}
		}
	}
}

func TestRequireCleanBaselineRejectsAnyPreexistingClientState(t *testing.T) {
	writeSnapshot := func(t *testing.T, snapshot fixtureproto.Snapshot) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "baseline.json")
		data, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	clean := fixtureproto.Snapshot{
		Adapters:             []fixtureproto.AdapterRecord{{InterfaceIndex: 7, InterfaceGUID: "{guid}", InterfaceAlias: "Ethernet", Status: "Up"}},
		Routes:               []fixtureproto.RouteRecord{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7, NextHop: "192.0.2.1", RouteMetric: 10}},
		DNS:                  []fixtureproto.DNSRecord{{InterfaceIndex: 7, InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.0.2.53"}}},
		Services:             []fixtureproto.ServiceRecord{{Name: agentServiceName, Present: false, Status: "Absent", StartMode: "Absent"}},
		Processes:            []fixtureproto.ProcessRecord{{Role: "agent", Present: false}, {Role: "core", Present: false}, {Role: "ui", Present: false}, {Role: "fake-upstream", Present: false}},
		OwnedFirewallRules:   []fixtureproto.FirewallRecord{{Name: "owned", Present: false, DefinitionSHA256: strings.Repeat("0", 64)}},
		MSIRegistrations:     []fixtureproto.MSIRecord{{ProductCode: "{D1234567-89AB-4CDE-8012-3456789ABCDE}", Present: false}},
		InstalledFiles:       []fixtureproto.FileRecord{{Role: "payload", Path: `C:\Program Files\RegenBio\OverseasAccess\overseas-agent.exe`, Present: false}},
		UnexpectedFiles:      []fixtureproto.FileRecord{},
		OwnedRoots:           []fixtureproto.RootRecord{{Path: `C:\Program Files\RegenBio\OverseasAccess`, Present: false}, {Path: `C:\ProgramData\RegenBio\OverseasAccess`, Present: false}},
		RuntimeFiles:         []fixtureproto.FileRecord{{Role: "credential", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`, Present: false}},
		RegistryRecords:      []fixtureproto.StateRecord{{Kind: "registry", Name: "product", Present: false}},
		OwnershipArtifacts:   []fixtureproto.StateRecord{{Kind: "ownership", Name: "ledger", Present: false}},
		RecoveryArtifacts:    []fixtureproto.StateRecord{{Kind: "recovery", Name: "machine", Present: false}},
		TransactionArtifacts: []fixtureproto.StateRecord{{Kind: "transaction", Name: "journal", Present: false}},
		FixtureResidues:      []fixtureproto.StateRecord{{Kind: "fixture-residue", Name: "service", Present: false}},
		Listeners:            []fixtureproto.ListenerRecord{{Role: "fake-upstream", Endpoint: "172.20.9.15:18083", Present: false}},
	}
	if err := requireCleanBaseline(writeSnapshot(t, clean)); err != nil {
		t.Fatalf("requireCleanBaseline(clean)=%v", err)
	}
	dirty := clean
	dirty.MSIRegistrations = []fixtureproto.MSIRecord{{ProductCode: "{D1234567-89AB-4CDE-8012-3456789ABCDE}", Present: true}}
	if err := requireCleanBaseline(writeSnapshot(t, dirty)); err == nil || !strings.Contains(err.Error(), "clean disposable baseline") {
		t.Fatalf("requireCleanBaseline(msi)=%v", err)
	}
	dirty = clean
	dirty.Adapters = []fixtureproto.AdapterRecord{{InterfaceIndex: 9, InterfaceGUID: "{tun}", InterfaceAlias: "RegenBioOverseasAccess", Status: "Up"}}
	if err := requireCleanBaseline(writeSnapshot(t, dirty)); err == nil || !strings.Contains(err.Error(), "clean disposable baseline") {
		t.Fatalf("requireCleanBaseline(tun)=%v", err)
	}
}
