//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"corp.example/overseas-access-gateway/internal/traceevent"
)

func TestPowerShellDiagnosticExtractsCLIXMLErrorAndDropsProgress(t *testing.T) {
	raw := []byte(`#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress"><MS><S N="StatusDescription">progress_marker</S></MS></Obj><S S="Error">firewall_marker_x000D__x000A_At line:1 char:1</S></Objs>`)
	err := newFixedNetworkOperationError(networkOperationBlock, errors.New("exit status 1"), raw)
	if err.DiagnosticStage() != traceevent.StageFirewallPublish || !strings.Contains(err.DiagnosticDetail(), "firewall_marker") {
		t.Fatalf("diagnostic = stage=%q detail=%q", err.DiagnosticStage(), err.DiagnosticDetail())
	}
	if strings.Contains(err.DiagnosticDetail(), "progress_marker") || strings.Contains(err.DiagnosticDetail(), "CLIXML") || strings.Contains(err.DiagnosticDetail(), `S="progress"`) {
		t.Fatalf("progress leaked into diagnostic: %q", err.DiagnosticDetail())
	}
}

func TestPowerShellDiagnosticSynthesizesDetailForEmptyStderr(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		context   context.Context
		err       error
		contains  string
		stage     string
	}{
		{"capture exit", networkOperationCapture, context.Background(), errors.New("exit status 7"), "exit status 7", traceevent.StageNetworkCapture},
		{"scan canceled", networkOperationScan, canceledContext(), errors.New("signal: killed"), "context canceled", traceevent.StageAdapterScan},
		{"restore deadline", networkOperationRestore, expiredContext(), errors.New("signal: killed"), "context deadline exceeded", traceevent.StageNetworkRestore},
		{"activate start", networkOperationActivate, context.Background(), errors.New("executable not found"), "executable not found", traceevent.StageRouteActivation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnostic := newFixedNetworkOperationErrorWithContext(test.context, test.operation, test.err, nil)
			if diagnostic.DiagnosticStage() != test.stage || diagnostic.DiagnosticDetail() == "" || !strings.Contains(diagnostic.DiagnosticDetail(), test.contains) {
				t.Fatalf("diagnostic = stage=%q detail=%q", diagnostic.DiagnosticStage(), diagnostic.DiagnosticDetail())
			}
		})
	}
}

func TestPowerShellRunnerSynthesizesEmptyStderrExit(t *testing.T) {
	original := networkPowerShellScripts[networkOperationActivate]
	networkPowerShellScripts[networkOperationActivate] = `exit 7`
	defer func() { networkPowerShellScripts[networkOperationActivate] = original }()
	_, err := (powerShellNetworkRunner{}).Run(context.Background(), networkOperationActivate, []byte(`{}`))
	diagnostic, ok := err.(stagedDiagnosticError)
	if !ok || diagnostic.DiagnosticStage() != traceevent.StageRouteActivation || !strings.Contains(diagnostic.DiagnosticDetail(), "exit status 7") {
		t.Fatalf("diagnostic = %#v", err)
	}
}

func TestPowerShellRunnerReportsDeadlineWithoutStderr(t *testing.T) {
	original := networkPowerShellScripts[networkOperationRestore]
	networkPowerShellScripts[networkOperationRestore] = `Start-Sleep -Seconds 5`
	defer func() { networkPowerShellScripts[networkOperationRestore] = original }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := (powerShellNetworkRunner{}).Run(ctx, networkOperationRestore, []byte(`{}`))
	diagnostic, ok := err.(stagedDiagnosticError)
	if !ok || diagnostic.DiagnosticStage() != traceevent.StageNetworkRestore || !strings.Contains(diagnostic.DiagnosticDetail(), "context deadline exceeded") {
		t.Fatalf("diagnostic = %#v", err)
	}
}

func TestPowerShellRunnerRedactsCredentialShapedStderr(t *testing.T) {
	original := networkPowerShellScripts[networkOperationBlock]
	networkPowerShellScripts[networkOperationBlock] = `throw 'password=Sup3rSecret!'`
	defer func() { networkPowerShellScripts[networkOperationBlock] = original }()
	_, err := (powerShellNetworkRunner{}).Run(context.Background(), networkOperationBlock, []byte(`{}`))
	diagnostic, ok := err.(stagedDiagnosticError)
	if !ok || strings.Contains(diagnostic.DiagnosticDetail(), "Sup3rSecret") || !strings.Contains(diagnostic.DiagnosticDetail(), "[REDACTED]") {
		t.Fatalf("diagnostic = %#v", err)
	}
}

func TestWindowsNetworkManagerTracesFixedOperationsWithoutInputDisclosure(t *testing.T) {
	sink := &recordingTraceSink{}
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store, WithWindowsTraceSink(sink))
	if err != nil {
		t.Fatal(err)
	}
	ctx := traceevent.WithGeneration(context.Background(), 42)
	seedActiveSnapshot(t, manager, store, runner)
	if err := manager.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Residue(ctx); err != nil {
		t.Fatal(err)
	}
	events := sink.eventsCopy()
	for _, stage := range []string{
		traceevent.StageNetworkRestore, traceevent.StageResidueVerify,
	} {
		if !containsString(traceKeys(events), stage+":"+traceevent.EventStarted) || !containsString(traceKeys(events), stage+":"+traceevent.EventSucceeded) {
			t.Fatalf("stage %q is incomplete: %v", stage, traceKeys(events))
		}
	}
	for _, event := range events {
		if event.Generation != 42 {
			t.Fatalf("generation = %d: %#v", event.Generation, event)
		}
		for _, forbidden := range []string{"172.20.9.15", "0.0.0.0/1", "128.0.0.0/1", "BlockedRemoteAddresses"} {
			if strings.Contains(event.Detail, forbidden) {
				t.Fatalf("trace leaked %q: %#v", forbidden, event)
			}
		}
	}
	assertTracePairs(t, events)
}

func TestWindowsNetworkResidueReportsCountsAndSnapshot(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), residue: windowsResidueCounts{ManagedRules: 23, ProductRoutes: 2, ProductTUNs: 1, CoreProcesses: 1}}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	seedActiveSnapshot(t, manager, store, runner)
	residue, err := manager.Residue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if residue.ManagedRules != 23 || residue.ProductRoutes != 2 || residue.ProductTUNs != 1 || residue.CoreProcesses != 1 || !residue.Snapshot || residue.SnapshotPhase != windowsSnapshotPhaseCaptured {
		t.Fatalf("residue = %#v", residue)
	}
}

func TestWindowsNetworkResidueRetainsExactOwnershipAfterRestore(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Residue(context.Background()); err != nil {
		t.Fatal(err)
	}
	input := runner.lastInputFor(t, networkOperationResidue)
	if input.OwnedTUN == nil || input.OwnedTUN.InterfaceGuid != validTUNIdentity().InterfaceGuid || len(input.OwnedRoutes) == 0 {
		t.Fatalf("residue ownership input = %#v", input)
	}
	if input.CoreExecutable != windowsCoreExecutable || input.FirewallGroup != windowsFirewallGroup {
		t.Fatalf("residue fixed identity = %#v", input)
	}
}

func TestNetworkOperationMessagesAreBusinessTexts(t *testing.T) {
	// dns_metric and firewall_arm carry dedicated business texts.
	for _, pair := range []struct{ operation, start, success string }{
		{networkOperationDNSMetric, "正在切换 DNS 与安全路由", "安全路由已启用"},
		{networkOperationFirewallArm, "正在启用防泄漏保护", "防泄漏保护已启用"},
	} {
		start, success := networkOperationMessages(pair.operation)
		if start != pair.start || success != pair.success {
			t.Fatalf("operation %s messages = %q / %q", pair.operation, start, success)
		}
	}
	if len(networkPowerShellScripts) == 0 {
		t.Fatal("no network operations registered")
	}
	for operation := range networkPowerShellScripts {
		start, success := networkOperationMessages(operation)
		if start == "" || success == "" {
			t.Fatalf("operation %s has no business messages", operation)
		}
		for _, forbidden := range []string{"固定网络操作", "network operation", operation} {
			if strings.Contains(start, forbidden) || strings.Contains(success, forbidden) {
				t.Fatalf("operation %s leaks generic or raw text: %q / %q", operation, start, success)
			}
		}
	}
}

func TestResiduePowerShellUsesOnlyFixedProductIdentities(t *testing.T) {
	for _, marker := range []string{
		"Get-NetFirewallRule -PolicyStore ActiveStore -Group", "Get-NetRoute -AddressFamily", "Get-NetAdapter -IncludeHidden",
		"Get-CimInstance Win32_Process", "OwnedRoutes", "OwnedTUN", "CoreExecutable", "DisabledPreparedRules",
	} {
		if !strings.Contains(residueNetworkPowerShell, marker) {
			t.Fatalf("residue script missing %q", marker)
		}
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	return ctx
}

func TestPowerShellInputEnvelopeIsASCIIAndRoundTripsUnicodeJSON(t *testing.T) {
	input := []byte(`{"InterfaceAlias":"以太网","Secondary":"本地连接"}`)
	envelope := powerShellInputEnvelope(input)
	for _, value := range envelope {
		if value > 0x7f {
			t.Fatalf("envelope contains non-ASCII byte %x", value)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(string(envelope))
	if err != nil || !bytes.Equal(decoded, input) {
		t.Fatalf("round trip = %q, %v", decoded, err)
	}
}

func TestPowerShellNetworkRunnerRoundTripsUnicodeUnderSystemCodePage(t *testing.T) {
	const operation = "transport_unicode_test"
	networkPowerShellScripts[operation] = `[pscustomobject]@{InterfaceAlias=[string]$i.InterfaceAlias;Secondary=[string]$i.Secondary}|ConvertTo-Json -Compress`
	defer delete(networkPowerShellScripts, operation)
	input := []byte(`{"InterfaceAlias":"以太网","Secondary":"本地连接"}`)
	output, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, input)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(output) {
		t.Fatalf("stdout is not UTF-8: %x", output)
	}
	var got map[string]string
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	if got["InterfaceAlias"] != "以太网" || got["Secondary"] != "本地连接" {
		t.Fatalf("round trip = %#v", got)
	}
}

func TestPowerShellNetworkRunnerRejectsInvalidUTF8Stdout(t *testing.T) {
	const operation = "transport_invalid_stdout_test"
	networkPowerShellScripts[operation] = `$stream=[Console]::OpenStandardOutput();$stream.WriteByte(255);$stream.Flush()`
	defer delete(networkPowerShellScripts, operation)
	if _, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "invalid PowerShell UTF-8 output") {
		t.Fatalf("invalid stdout error = %v", err)
	}
}

func TestPowerShellNetworkRunnerRejectsInvalidUTF8InputBeforeScriptBody(t *testing.T) {
	const operation = "transport_invalid_input_test"
	networkPowerShellScripts[operation] = `Write-Output 'script_body_reached'`
	defer delete(networkPowerShellScripts, operation)
	if output, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, []byte{0xff}); err == nil || bytes.Contains(output, []byte("script_body_reached")) {
		t.Fatalf("invalid input reached body: output=%q err=%v", output, err)
	}
}

func TestPowerShellTransportSuppressesProgressBeforeFailure(t *testing.T) {
	const operation = networkOperationBlock
	original := networkPowerShellScripts[operation]
	networkPowerShellScripts[operation] = `Write-Progress -Activity noisy -Completed;throw 'transport_marker'`
	defer func() { networkPowerShellScripts[operation] = original }()
	_, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, []byte(`{}`))
	diagnostic, ok := err.(interface{ DiagnosticDetail() string })
	if !ok || !strings.Contains(diagnostic.DiagnosticDetail(), "transport_marker") || strings.Contains(diagnostic.DiagnosticDetail(), `S="progress"`) {
		t.Fatalf("diagnostic = %#v", err)
	}
}

func TestWindowsPowerShellNormalizesActiveStoreIPv4SubnetMasks(t *testing.T) {
	const operation = "normalize_active_store_address_test"
	marker := "function Assert-EqualAddressSet"
	functionEnd := strings.Index(verifyNetworkPowerShell, marker)
	if functionEnd < 0 {
		t.Fatalf("Normalize-AddressToken function boundary %q is missing", marker)
	}
	normalizeFunction := verifyNetworkPowerShell[strings.Index(verifyNetworkPowerShell, "function Normalize-AddressToken"):functionEnd]
	networkPowerShellScripts[operation] = normalizeFunction + `
@(
  (Normalize-AddressToken '1.0.0.0/255.0.0.0'),
  (Normalize-AddressToken '198.51.100.7/255.255.255.255'),
  (Normalize-AddressToken '203.0.112.0/255.255.240.0'),
  (Normalize-AddressToken '2001:db8::/32')
) | ConvertTo-Json -Compress`
	defer delete(networkPowerShellScripts, operation)

	output, err := (powerShellNetworkRunner{}).Run(context.Background(), operation, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	want := []string{"1.0.0.0/8", "198.51.100.7", "203.0.112.0/20", "2001:db8::/32"}
	if !slices.Equal(got, want) {
		t.Fatalf("normalized addresses = %#v, want %#v", got, want)
	}
}

func TestPowerShellNetworkDiagnosticIsBoundedAndDoesNotIncludeInput(t *testing.T) {
	input := []byte(`{"credential":"never-copy-this-input"}`)
	raw := []byte("adapter_identity_join:\r\n" + strings.Repeat("x", 1000) + "\x00")
	detail := sanitizePowerShellDetail(raw)
	if len(detail) > maxNetworkDiagnosticBytes || !utf8.ValidString(detail) {
		t.Fatalf("diagnostic length/encoding = %d/%v", len(detail), utf8.ValidString(detail))
	}
	if strings.ContainsAny(detail, "\r\n\x00") || strings.Contains(detail, string(input)) {
		t.Fatalf("unsafe diagnostic %q", detail)
	}
	err := newFixedNetworkOperationError(networkOperationScan, errors.New("exit status 1"), raw)
	if err.DiagnosticStage() != traceevent.StageAdapterScan || err.DiagnosticDetail() != detail || strings.Contains(err.Error(), string(input)) {
		t.Fatalf("typed diagnostic = stage=%q detail=%q error=%q", err.DiagnosticStage(), err.DiagnosticDetail(), err.Error())
	}
}

func TestWindowsNetworkActivateUsesFixedTUNRoutesAndDNS(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	armTestTUN(manager, runner)
	seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}

	applier := manager.routes.(*testRouteApplier)
	if len(applier.applied) == 0 {
		t.Fatal("routes were not applied")
	}
	if applier.applied[0].OwnedTUN == nil || applier.applied[0].OwnedTUN.InterfaceGuid != "new-tun-guid" || len(applier.applied[0].OwnedRoutes) == 0 {
		t.Fatalf("owned TUN activation input = %#v", applier.applied[0])
	}
	assertOwnedRouteCovers(t, applier.applied[0].OwnedRoutes, netip.MustParseAddr("8.8.8.8"), windowsOwnedRouteMetric, validTUNIdentity().InterfaceIndex)
	dns := runner.inputFor(t, networkOperationDNSMetric)
	if dns.TUNInterface != windowsTUNInterface || dns.TUNDNS != windowsTUNDNS || !dns.DNSConnected {
		t.Fatalf("dns metric input = %#v", dns)
	}
}

func TestWindowsNetworkRestoreDeletesSnapshotOnlyAfterSuccess(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), restoreErrors: []error{errors.New("restore failed"), nil}}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := seedActiveSnapshot(t, manager, store, runner)

	if err := manager.Restore(context.Background(), snapshot); err == nil {
		t.Fatal("first Restore() succeeded")
	}
	if !store.exists {
		t.Fatal("failed restore deleted the persisted snapshot")
	}
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("second Restore() = %v", err)
	}
	if store.exists {
		t.Fatal("successful restore retained the persisted snapshot")
	}
}

func TestWindowsNetworkCapturedOnlyRestoreDoesNotRewriteInterfaces(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := seedActiveSnapshot(t, manager, store, runner)
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	input := runner.inputFor(t, networkOperationRestore)
	if input.RestoreInterfaces {
		t.Fatal("captured-only restore rewrites interfaces")
	}
	if !strings.Contains(restoreNetworkPowerShell, "if ([bool]$i.RestoreInterfaces)") {
		t.Fatal("restore script does not gate interface mutation by ownership phase")
	}
}

func TestWindowsPowerShellRestoreSkipsMissingOwnedRoutes(t *testing.T) {
	if !strings.Contains(restoreNetworkPowerShell, `foreach ($route in @($i.OwnedRoutes | Where-Object { $null -ne $_ }))`) {
		t.Fatal("restore script treats a missing OwnedRoutes property as one null route")
	}
}

func TestWindowsNetworkTUNOwnedRestoreUsesStableInterfaceGUID(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	armTestTUN(manager, runner)
	seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), store.snapshot); err != nil {
		t.Fatal(err)
	}
	input := runner.inputFor(t, networkOperationRestore)
	if !input.RestoreInterfaces || input.Interfaces[0].InterfaceGuid != "physical-guid" {
		t.Fatalf("TUN-owned restore input = %#v", input)
	}
	for _, required := range []string{"Get-NetAdapter -IncludeHidden", "InterfaceGuid", "InterfaceIndex", "$matches.Count -ne 1"} {
		if !strings.Contains(restoreNetworkPowerShell, required) {
			t.Fatalf("restore script does not contain %q", required)
		}
	}
}

func TestWindowsNetworkReconcileIsIdempotentAcrossServiceRestart(t *testing.T) {
	snapshot := capturedWindowsSnapshot(t)
	runner := &fakeNetworkRunner{}
	store := &fakeSnapshotStore{exists: true, snapshot: snapshot}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runner.count(networkOperationRestore); got != 2 {
		t.Fatalf("restore operations = %d, want one snapshot restore and one orphan cleanup", got)
	}
	input := runner.lastInputFor(t, networkOperationRestore)
	if input.RestoreInterfaces || len(input.OwnedRoutes) != 0 {
		t.Fatalf("second reconciliation was not a non-invasive orphan cleanup: %#v", input)
	}
}

func TestWindowsNetworkPublicBlockExemptsCorporateDNSAddresses(t *testing.T) {
	policy := validPolicy()
	policy.CorporateDNS = []string{"8.8.8.8"}
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("8.8.8.8"), false)
}

func TestWindowsNetworkCanonicalIPv4GlobalReachabilityExceptions(t *testing.T) {
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"192.0.0.9", "192.0.0.10", "192.31.196.1", "192.52.193.1", "192.175.48.1",
	} {
		assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr(value), true)
	}
	for _, value := range []string{
		"192.0.0.7", "192.0.0.8", "192.0.0.11", "192.0.0.170", "192.0.0.171",
		"192.0.2.1", "192.88.99.1", "192.88.99.2",
	} {
		assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr(value), false)
	}
}

func TestWindowsNetworkCanonicalIPv4ExceptionsReachFirewallAndTUNRoutes(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Restore(context.Background(), snapshot) })

	tun := manager.routes.(*testRouteApplier).applied[0].OwnedRoutes
	for _, value := range []string{"192.0.0.9", "192.0.0.10"} {
		address := netip.MustParseAddr(value)
		assertAddressCovered(t, manager.blockedPrefixes, address, true)
		assertOwnedRouteCovers(t, tun, address, windowsOwnedRouteMetric, validTUNIdentity().InterfaceIndex)
	}
	dns := runner.inputFor(t, networkOperationDNSMetric)
	if dns.TUNInterface != windowsTUNInterface || dns.TUNDNS != windowsTUNDNS || !dns.DNSConnected {
		t.Fatalf("dns metric input = %#v", dns)
	}
}

func TestWindowsNetworkBlocksPublicIPv6AndRetainsLocalIPv6(t *testing.T) {
	policy := validPolicy()
	policy.CorporateCIDRs = append(policy.CorporateCIDRs, "2606:4700:4700::/48")
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("2001:4860:4860::8888"), true)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("2606:4700:4700::1111"), false)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("::1"), false)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("fe80::1"), false)
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("fd00::1"), false)
}

func TestWindowsNetworkRestoreFailureRearmsEmergency(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot(), runErrors: map[string][]error{networkOperationRestore: {errors.New("partial firewall removal")}}}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := seedActiveSnapshot(t, manager, store, runner)
	if err := manager.Restore(context.Background(), snapshot); err == nil {
		t.Fatal("Restore() succeeded after partial removal")
	}
	if !store.exists || runner.count(networkOperationEmergency) == 0 {
		t.Fatalf("failed restore did not retain snapshot/emergency: exists=%v emergency=%d", store.exists, runner.count(networkOperationEmergency))
	}
	if !strings.Contains(restoreNetworkPowerShell, "catch") || !strings.Contains(restoreNetworkPowerShell, "Install-Emergency") {
		t.Fatal("restore script cannot re-arm emergency protection inside a partial-removal failure")
	}
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("retry Restore() = %v", err)
	}
}

func TestWindowsNetworkRestoreValidationFailureArmsEmergency(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := seedActiveSnapshot(t, manager, store, runner)
	manager.mu.Lock()
	manager.current.OwnershipPhase = "tampered"
	manager.mu.Unlock()
	if err := manager.Restore(context.Background(), snapshot); err == nil {
		t.Fatal("Restore() accepted a tampered current snapshot")
	}
	if got := runner.count(networkOperationEmergency); got == 0 {
		t.Fatal("validation failure did not install emergency protection")
	}
	if !strings.Contains(preparedFirewallDisablePowerShell, "refusing to disable unknown product-group rule") {
		t.Fatal("prepared disable can adopt a foreign colliding rule")
	}
}

func TestWindowsNetworkRestoreMalformedInputArmsEmergencyProtection(t *testing.T) {
	runner := &fakeNetworkRunner{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), struct{}{}); err == nil {
		t.Fatal("Restore() accepted malformed input")
	}
	if got := runner.count(networkOperationEmergency); got == 0 {
		t.Fatal("malformed restore input did not install emergency protection")
	}
	if got := runner.count(networkOperationEmergency); got != 1 {
		t.Fatalf("emergency operations = %d, want exactly one", got)
	}
}

func TestWindowsNetworkReconcileFailureRearmsEmergency(t *testing.T) {
	runner := &fakeNetworkRunner{runErrors: map[string][]error{networkOperationRestore: {errors.New("restore failed")}}}
	store := &fakeSnapshotStore{exists: true, snapshot: capturedWindowsSnapshot(t)}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile() succeeded after restore failure")
	}
	if !store.exists || runner.count(networkOperationEmergency) == 0 {
		t.Fatalf("failed reconcile did not retain snapshot/emergency: exists=%v emergency=%d", store.exists, runner.count(networkOperationEmergency))
	}
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("retry Reconcile() = %v", err)
	}
}

func TestWindowsNetworkReconcileValidationFailureArmsEmergency(t *testing.T) {
	corrupt := validWindowsSnapshot()
	corrupt.Version = 0
	runner := &fakeNetworkRunner{}
	store := &fakeSnapshotStore{exists: true, snapshot: corrupt}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile() accepted corrupt persisted state")
	}
	if !store.exists || runner.count(networkOperationEmergency) == 0 {
		t.Fatalf("validation failure did not retain snapshot/emergency: exists=%v emergency=%d", store.exists, runner.count(networkOperationEmergency))
	}
}

func TestWindowsNetworkReconcileRejectsTamperedOwnedRouteTuplesBeforeCleanup(t *testing.T) {
	base := fullyOwnedWindowsSnapshot(t)
	validRunner := &fakeNetworkRunner{}
	validStore := &fakeSnapshotStore{exists: true, snapshot: cloneWindowsSnapshot(base)}
	validManager, err := newWindowsNetworkManager(validPolicy(), `C:\valid-state.json`, validRunner, validStore)
	if err != nil {
		t.Fatal(err)
	}
	if err := validManager.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() rejected canonical owned routes: %v", err)
	}
	if got := validRunner.count(networkOperationRestore); got != 1 {
		t.Fatalf("canonical destructive restore operations = %d, want 1", got)
	}
	tests := []struct {
		name   string
		mutate func(*WindowsNetworkSnapshot)
	}{
		{name: "firewall prefix", mutate: func(value *WindowsNetworkSnapshot) { value.BlockedRemoteAddresses[0] = "8.8.8.0/24" }},
		{name: "unsupported guard", mutate: func(value *WindowsNetworkSnapshot) {
			value.GuardRoutes = []WindowsOwnedRoute{{AddressFamily: "IPv4", DestinationPrefix: "8.8.8.0/24", InterfaceIndex: 1, NextHop: "0.0.0.0", RouteMetric: 8192}}
		}},
		{name: "TUN prefix", mutate: func(value *WindowsNetworkSnapshot) { value.OwnedRoutes[0].DestinationPrefix = "8.8.8.0/24" }},
		{name: "TUN family", mutate: func(value *WindowsNetworkSnapshot) { value.OwnedRoutes[0].AddressFamily = "IPv6" }},
		{name: "TUN interface", mutate: func(value *WindowsNetworkSnapshot) { value.OwnedRoutes[0].InterfaceIndex++ }},
		{name: "TUN metric", mutate: func(value *WindowsNetworkSnapshot) { value.OwnedRoutes[0].RouteMetric++ }},
		{name: "TUN next hop", mutate: func(value *WindowsNetworkSnapshot) { value.OwnedRoutes[0].NextHop = "192.0.2.1" }},
		{name: "TUN duplicate", mutate: func(value *WindowsNetworkSnapshot) {
			value.OwnedRoutes = append(value.OwnedRoutes, value.OwnedRoutes[0])
		}},
		{name: "TUN identity", mutate: func(value *WindowsNetworkSnapshot) { value.OwnedTUN.InterfaceAlias = "foreign-tun" }},
		{name: "TUN identity relation", mutate: func(value *WindowsNetworkSnapshot) { value.OwnedTUN.InterfaceIndex++ }},
		{name: "missing physical GUID", mutate: func(value *WindowsNetworkSnapshot) { value.Interfaces[0].InterfaceGuid = "" }},
		{name: "duplicate physical GUID", mutate: func(value *WindowsNetworkSnapshot) {
			duplicate := value.Interfaces[0]
			duplicate.Index++
			duplicate.Alias = "Duplicate Ethernet"
			value.Interfaces = append(value.Interfaces, duplicate)
		}},
		{name: "physical GUID collides with TUN", mutate: func(value *WindowsNetworkSnapshot) {
			value.Interfaces[0].InterfaceGuid = value.OwnedTUN.InterfaceGuid
		}},
		{name: "cleared TUN ownership", mutate: func(value *WindowsNetworkSnapshot) {
			value.OwnedTUN = nil
			value.OwnedRoutes = nil
		}},
		{name: "coherently redirected TUN ownership", mutate: func(value *WindowsNetworkSnapshot) {
			value.OwnedTUN.InterfaceIndex++
			value.OwnedTUN.InterfaceGuid = "redirected-tun-guid"
			for index := range value.OwnedRoutes {
				if value.OwnedRoutes[index].RouteMetric == windowsOwnedRouteMetric {
					value.OwnedRoutes[index].InterfaceIndex = value.OwnedTUN.InterfaceIndex
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneWindowsSnapshot(base)
			test.mutate(&snapshot)
			runner := &fakeNetworkRunner{}
			store := &fakeSnapshotStore{exists: true, snapshot: snapshot}
			manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Reconcile(context.Background()); err == nil {
				t.Fatal("Reconcile() accepted a tampered owned route tuple")
			}
			if got := runner.count(networkOperationRestore); got != 0 {
				t.Fatalf("destructive restore operations = %d, want 0", got)
			}
			if got := runner.count(networkOperationEmergency); got == 0 {
				t.Fatal("tampered snapshot did not re-arm emergency protection")
			}
		})
	}
}

func TestWindowsNetworkReconcileRejectsCoherentlyRedirectedNodeBypass(t *testing.T) {
	capture := validWindowsSnapshot()
	capture.NodeRoutes[0] = WindowsNodeRouteSnapshot{
		NodeAddress: "172.20.9.15", DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7,
		NextHop: "172.20.10.1", RouteMetric: 13, InterfaceMetric: 25, EffectiveMetric: 38, BypassRequired: true,
	}
	snapshot := fullyOwnedWindowsSnapshotFromCapture(t, capture)
	snapshot.NodeRoutes[0].InterfaceIndex = 12
	snapshot.NodeRoutes[0].NextHop = "192.0.2.1"
	snapshot.NodeRoutes[0].RouteMetric = 7
	snapshot.NodeRoutes[0].InterfaceMetric = 11
	snapshot.NodeRoutes[0].EffectiveMetric = 18
	for index := range snapshot.OwnedRoutes {
		if snapshot.OwnedRoutes[index].DestinationPrefix == "172.20.9.15/32" {
			snapshot.OwnedRoutes[index].InterfaceIndex = 12
			snapshot.OwnedRoutes[index].NextHop = "192.0.2.1"
			snapshot.OwnedRoutes[index].RouteMetric = 7
		}
	}
	runner := &fakeNetworkRunner{}
	store := &fakeSnapshotStore{exists: true, snapshot: snapshot}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile() accepted coherently redirected node bypass ownership")
	}
	if got := runner.count(networkOperationRestore); got != 0 {
		t.Fatalf("destructive restore operations = %d, want 0", got)
	}
	if got := runner.count(networkOperationEmergency); got == 0 {
		t.Fatal("coherent node-route tampering did not re-arm emergency protection")
	}
}

func TestWindowsNetworkDNSProtectionBlocksSecondaryPrivateAndPublicResolvers(t *testing.T) {
	policy := validPolicy()
	policy.CorporateDNS = []string{"172.20.9.1", "172.20.9.2"}
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("192.168.50.53"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("8.8.8.8"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("fd00::53"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("172.20.9.1"), false)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("172.19.0.2"), false)
	if !strings.Contains(blockNetworkPowerShell, "-RemotePort 53") || !strings.Contains(blockNetworkPowerShell, "$i.DNSBlockedRemoteAddresses") {
		t.Fatal("dedicated all-destination DNS egress rules are missing")
	}
}

func TestNormalizeWindowsFirewallPrefixesSplitsIPv6DefaultAndDeduplicates(t *testing.T) {
	input := []string{"10.0.0.0/8", "::/0", "::/1", "192.0.2.1/32", "::/0"}
	want := []string{"10.0.0.0/8", "::/1", "8000::/1", "192.0.2.1/32"}
	if got := normalizeWindowsFirewallPrefixes(input); !slices.Equal(got, want) {
		t.Fatalf("normalized = %#v, want %#v", got, want)
	}
}

func TestWindowsNetworkDNSFirewallPrefixesExcludeRejectedIPv6Default(t *testing.T) {
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, &fakeNetworkRunner{}, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(manager.dnsBlockedPrefixes, "::/0") || !slices.Contains(manager.dnsBlockedPrefixes, "::/1") || !slices.Contains(manager.dnsBlockedPrefixes, "8000::/1") {
		t.Fatalf("DNS firewall prefixes = %#v", manager.dnsBlockedPrefixes)
	}
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("2001:4860:4860::8888"), true)
	assertAddressCovered(t, manager.dnsBlockedPrefixes, netip.MustParseAddr("fd00::53"), true)
}

func TestWindowsNetworkEveryFirewallPhaseUsesNormalizedDNSPrefixes(t *testing.T) {
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := seedActiveSnapshot(t, manager, store, runner)
	if !slices.Equal(snapshot.DNSBlockedRemoteAddresses, manager.dnsBlockedPrefixes) {
		t.Fatalf("snapshot DNS prefixes = %#v", snapshot.DNSBlockedRemoteAddresses)
	}
	if err := manager.installEmergencyProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	emergency := runner.inputFor(t, networkOperationEmergency)
	if !slices.Equal(emergency.DNSBlockedRemoteAddresses, manager.dnsBlockedPrefixes) || slices.Contains(emergency.DNSBlockedRemoteAddresses, "::/0") {
		t.Fatalf("emergency DNS prefixes = %#v", emergency.DNSBlockedRemoteAddresses)
	}
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	input := runner.inputFor(t, networkOperationRestore)
	if !slices.Equal(input.DNSBlockedRemoteAddresses, manager.dnsBlockedPrefixes) || slices.Contains(input.DNSBlockedRemoteAddresses, "::/0") {
		t.Fatalf("restore DNS prefixes = %#v", input.DNSBlockedRemoteAddresses)
	}
}

func TestWindowsNetworkUsesCapturedBestRouteForEveryNodeBypass(t *testing.T) {
	policy := validPolicy()
	policy.Nodes = append(policy.Nodes, accessmodel.Node{ID: "second", Address: "8.8.4.4", Port: 8443, Priority: 2})
	snapshot := validWindowsSnapshot()
	snapshot.NodeRoutes = []WindowsNodeRouteSnapshot{
		{NodeAddress: "172.20.9.15", DestinationPrefix: "172.20.8.0/22", InterfaceIndex: 7, NextHop: "0.0.0.0", RouteMetric: 20, InterfaceMetric: 25, EffectiveMetric: 45, BypassRequired: false},
		{NodeAddress: "8.8.4.4", DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 12, NextHop: "192.0.2.1", RouteMetric: 7, InterfaceMetric: 11, EffectiveMetric: 18, BypassRequired: true},
	}
	runner := &fakeNetworkRunner{capture: snapshot, ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(policy, `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	armTestTUN(manager, runner)
	seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertAddressCovered(t, manager.blockedPrefixes, netip.MustParseAddr("8.8.4.4"), false)

	applier := manager.routes.(*testRouteApplier)
	if len(applier.applied) == 0 {
		t.Fatal("routes were not applied")
	}
	input := applier.applied[0]
	var bypass *WindowsOwnedRoute
	for index := range input.OwnedRoutes {
		if input.OwnedRoutes[index].DestinationPrefix == "8.8.4.4/32" {
			bypass = &input.OwnedRoutes[index]
		}
		if input.OwnedRoutes[index].DestinationPrefix == "172.20.9.15/32" {
			t.Fatal("created unnecessary bypass despite more-specific on-link route")
		}
	}
	if bypass == nil || bypass.InterfaceIndex != 12 || bypass.NextHop != "192.0.2.1" || bypass.RouteMetric != 7 {
		t.Fatalf("captured best-route bypass = %#v", bypass)
	}
}

func TestWindowsNetworkRestoreCarriesFullOwnedRouteTuples(t *testing.T) {
	snapshot := validWindowsSnapshot()
	snapshot.NodeRoutes = []WindowsNodeRouteSnapshot{{
		NodeAddress: "172.20.9.15", DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 7,
		NextHop: "172.20.10.1", RouteMetric: 13, InterfaceMetric: 25, EffectiveMetric: 38, BypassRequired: true,
	}}
	runner := &fakeNetworkRunner{capture: snapshot, ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	captured := seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background(), captured); err != nil {
		t.Fatal(err)
	}

	input := runner.inputFor(t, networkOperationRestore)
	if len(input.OwnedRoutes) < 2 || len(input.GuardRoutes) != 0 {
		t.Fatalf("owned routes were not carried or guard routes returned: owned=%d guard=%d", len(input.OwnedRoutes), len(input.GuardRoutes))
	}
	for _, route := range input.OwnedRoutes {
		if route.DestinationPrefix == "" || route.InterfaceIndex <= 0 || route.NextHop == "" {
			t.Fatalf("incomplete owned route tuple: %#v", route)
		}
		if route.DestinationPrefix == "172.20.9.15/32" && route.RouteMetric != 13 {
			t.Fatalf("bypass did not preserve captured route metric: %#v", route)
		}
	}
	if !strings.Contains(restoreNetworkPowerShell, "$_.InterfaceIndex -eq") || !strings.Contains(restoreNetworkPowerShell, "$_.NextHop -eq") {
		t.Fatal("restore script does not match the full owned route tuple")
	}
}

func TestWindowsNetworkReadinessRejectsUnownedOrMalformedTUN(t *testing.T) {
	tests := []struct {
		name     string
		identity WindowsTUNIdentity
	}{
		{name: "preexisting guid", identity: func() WindowsTUNIdentity {
			value := validTUNIdentity()
			value.InterfaceGuid = "baseline-guid"
			return value
		}()},
		{name: "wrong alias", identity: func() WindowsTUNIdentity {
			value := validTUNIdentity()
			value.InterfaceAlias = "Ethernet"
			return value
		}()},
		{name: "missing guid", identity: func() WindowsTUNIdentity { value := validTUNIdentity(); value.InterfaceGuid = ""; return value }()},
		{name: "wrong address", identity: func() WindowsTUNIdentity {
			value := validTUNIdentity()
			value.Addresses = []string{"172.19.0.5/30"}
			return value
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := validWindowsSnapshot()
			snapshot.BaselineAdapterGuids = []string{"baseline-guid"}
			runner := &fakeNetworkRunner{capture: snapshot, ready: test.identity}
			store := &fakeSnapshotStore{}
			manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
			armTestTUN(manager, runner)
			if err != nil {
				t.Fatal(err)
			}
			seedActiveSnapshot(t, manager, store, runner)
			if err := manager.WaitTUNReady(context.Background()); err == nil {
				t.Fatal("WaitTUNReady() accepted an unowned or malformed adapter")
			} else if !errors.Is(err, errTUNIdentityMismatch) {
				t.Fatalf("WaitTUNReady() error = %v, want identity mismatch", err)
			}
		})
	}
}

func TestWindowsNetworkReadinessAcceptsNewFixedIdentityWithoutDriverMetadataHeuristic(t *testing.T) {
	identity := validTUNIdentity()
	identity.InterfaceDescription = "sing-tun"
	identity.Virtual = false

	snapshot := validWindowsSnapshot()
	snapshot.BaselineAdapterGuids = []string{"baseline-guid"}
	runner := &fakeNetworkRunner{capture: snapshot, ready: identity}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatalf("WaitTUNReady() rejected a newly created fixed-identity TUN: %v", err)
	}
	if err := manager.ActivateTUNRoutes(context.Background()); err != nil {
		t.Fatalf("ActivateTUNRoutes() rejected the accepted fixed-identity TUN: %v", err)
	}
	for _, mutableMetadata := range []string{"InterfaceDescription", "HardwareInterface", "Virtual"} {
		if strings.Contains(activateNetworkPowerShell, mutableMetadata) {
			t.Fatalf("activation script still depends on mutable adapter metadata %q", mutableMetadata)
		}
	}
}

func TestWindowsNetworkReconcileWithoutSnapshotRemovesOrphanedManagedRules(t *testing.T) {
	runner := &fakeNetworkRunner{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, &fakeSnapshotStore{})
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runner.count(networkOperationRestore); got != 1 {
		t.Fatalf("restore operations = %d, want 1 orphan cleanup", got)
	}
	input := runner.inputFor(t, networkOperationRestore)
	if input.RestoreInterfaces || input.FirewallGroup != windowsFirewallGroup || len(input.OwnedRoutes) != 0 {
		t.Fatalf("orphan cleanup input = %#v", input)
	}
}

func validWindowsSnapshot() WindowsNetworkSnapshot {
	return WindowsNetworkSnapshot{
		Version: 1,
		Interfaces: []WindowsInterfaceSnapshot{{
			Index:           7,
			InterfaceGuid:   "physical-guid",
			Alias:           "Ethernet",
			InterfaceMetric: 25,
			AutomaticMetric: true,
			DNSAutomatic:    true,
			DNSServers:      []string{"172.20.9.1", "172.20.9.2"},
		}},
		RouteMetric:          windowsOwnedRouteMetric,
		BaselineAdapterGuids: []string{"baseline-guid"},
		NodeRoutes: []WindowsNodeRouteSnapshot{{
			NodeAddress: "172.20.9.15", DestinationPrefix: "172.20.8.0/22", InterfaceIndex: 7,
			NextHop: "0.0.0.0", RouteMetric: 20, InterfaceMetric: 25, EffectiveMetric: 45,
		}},
	}
}

func fullyOwnedWindowsSnapshot(t *testing.T) WindowsNetworkSnapshot {
	t.Helper()
	return fullyOwnedWindowsSnapshotFromCapture(t, validWindowsSnapshot())
}

func fullyOwnedWindowsSnapshotFromCapture(t *testing.T, capture WindowsNetworkSnapshot) WindowsNetworkSnapshot {
	t.Helper()
	runner := &fakeNetworkRunner{capture: capture, ready: validTUNIdentity()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	armTestTUN(manager, runner)
	if err != nil {
		t.Fatal(err)
	}
	armTestTUN(manager, runner)
	armTestTUN(manager, runner)
	seedActiveSnapshot(t, manager, store, runner)
	if err := manager.WaitTUNReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store.snapshot
}

// testTUNNative decorates the production native reader so WaitTUNReady can be
// exercised without a real wintun adapter.
type testTUNNative struct {
	inner nativeNetworkReader
	tun   WindowsTUNIdentity
	found bool
	err   error
}

func (n *testTUNNative) Baseline(ctx context.Context, nodes []string) (WindowsNetworkBaseline, error) {
	return n.inner.Baseline(ctx, nodes)
}

func (n *testTUNNative) Fingerprint(ctx context.Context, nodes []string) (string, error) {
	return n.inner.Fingerprint(ctx, nodes)
}

func (n *testTUNNative) TUNReady(ctx context.Context, alias, address string, baseline []string) (WindowsTUNIdentity, bool, error) {
	return n.tun, n.found, n.err
}

type testRouteApplier struct {
	mu       sync.Mutex
	applied  []WindowsNetworkSnapshot
	revoked  []WindowsNetworkSnapshot
	applyErr error
}

func (a *testRouteApplier) ApplyOwnedRoutes(snapshot WindowsNetworkSnapshot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applyErr != nil {
		return a.applyErr
	}
	a.applied = append(a.applied, snapshot)
	return nil
}

func (a *testRouteApplier) RevokeOwnedRoutes(snapshot WindowsNetworkSnapshot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revoked = append(a.revoked, snapshot)
	return nil
}

// armTestTUN wires the TUN detection stub and a recording route applier from
// the runner fixture: a configured ready identity means present-and-ready;
// otherwise not found.
func armTestTUN(manager *WindowsNetworkManager, runner *fakeNetworkRunner) *testRouteApplier {
	applier := &testRouteApplier{}
	manager.routes = applier
	if runner.ready.InterfaceAlias != "" || runner.ready.InterfaceGuid != "" {
		manager.native = &testTUNNative{inner: manager.native, tun: runner.ready, found: true}
		return applier
	}
	manager.native = &testTUNNative{inner: manager.native}
	return applier
}

// seedActiveSnapshot installs the fixture as the manager's persisted captured
// snapshot exactly the way the production capture path does, without invoking
// any legacy PowerShell capture operation.
func seedActiveSnapshot(t *testing.T, manager *WindowsNetworkManager, store *fakeSnapshotStore, runner *fakeNetworkRunner) WindowsNetworkSnapshot {
	t.Helper()
	snapshot := cloneWindowsSnapshot(runner.capture)
	snapshot.Version = 1
	snapshot.RouteMetric = windowsOwnedRouteMetric
	snapshot.OwnershipPhase = windowsSnapshotPhaseCaptured
	snapshot.BlockedRemoteAddresses = append([]string(nil), manager.blockedPrefixes...)
	snapshot.DNSBlockedRemoteAddresses = append([]string(nil), manager.dnsBlockedPrefixes...)
	if err := sealWindowsSnapshot(&snapshot); err != nil {
		t.Fatal(err)
	}
	if err := manager.validateWindowsSnapshot(snapshot); err != nil {
		t.Fatalf("seeded snapshot is invalid: %v", err)
	}
	if err := store.Save(manager.statePath, snapshot); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	current := snapshot
	manager.current = &current
	manager.mu.Unlock()
	return snapshot
}

func capturedWindowsSnapshot(t *testing.T) WindowsNetworkSnapshot {
	t.Helper()
	runner := &fakeNetworkRunner{capture: validWindowsSnapshot()}
	store := &fakeSnapshotStore{}
	manager, err := newWindowsNetworkManager(validPolicy(), `C:\state.json`, runner, store)
	if err != nil {
		t.Fatal(err)
	}
	armTestTUN(manager, runner)
	return seedActiveSnapshot(t, manager, store, runner)
}

func cloneWindowsSnapshot(value WindowsNetworkSnapshot) WindowsNetworkSnapshot {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var clone WindowsNetworkSnapshot
	if err := json.Unmarshal(encoded, &clone); err != nil {
		panic(err)
	}
	return clone
}

func validTUNIdentity() WindowsTUNIdentity {
	return WindowsTUNIdentity{
		InterfaceIndex:       41,
		InterfaceGuid:        "new-tun-guid",
		InterfaceAlias:       windowsTUNInterface,
		InterfaceDescription: "Wintun Userspace Tunnel",
		HardwareInterface:    false,
		Virtual:              true,
		Addresses:            []string{"172.19.0.1/30"},
	}
}

func assertAddressCovered(t *testing.T, prefixes []string, address netip.Addr, want bool) {
	t.Helper()
	covered := false
	for _, value := range prefixes {
		if netip.MustParsePrefix(value).Contains(address) {
			covered = true
			break
		}
	}
	if covered != want {
		t.Fatalf("address %s covered = %v, want %v (prefixes=%v)", address, covered, want, prefixes)
	}
}

func assertOwnedRouteCovers(t *testing.T, routes []WindowsOwnedRoute, address netip.Addr, metric, interfaceIndex int) {
	t.Helper()
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.DestinationPrefix)
		if err == nil && prefix.Contains(address) && route.RouteMetric == metric && route.InterfaceIndex == interfaceIndex {
			return
		}
	}
	t.Fatalf("no owned route covers %s with metric=%d interface=%d: %#v", address, metric, interfaceIndex, routes)
}

func mostSpecificOwnedRoute(routes []WindowsOwnedRoute, address netip.Addr) *WindowsOwnedRoute {
	var best *WindowsOwnedRoute
	for index := range routes {
		prefix, err := netip.ParsePrefix(routes[index].DestinationPrefix)
		if err != nil || !prefix.Contains(address) {
			continue
		}
		if best == nil || prefix.Bits() > netip.MustParsePrefix(best.DestinationPrefix).Bits() {
			best = &routes[index]
		}
	}
	return best
}

func firstIndex(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return len(values)
}

type fakeNetworkRunner struct {
	trace               *callTrace
	capture             WindowsNetworkSnapshot
	ready               WindowsTUNIdentity
	operations          []string
	inputs              map[string][]byte
	restoreErrors       []error
	scans               [][]WindowsAdapterIdentity
	inputHistory        map[string][][]byte
	mu                  sync.Mutex
	runErrors           map[string][]error
	blockScanAfter      int
	scanCalls           int
	scanStarted         chan struct{}
	scanStartOnce       sync.Once
	emergencyContextErr error
	residue             windowsResidueCounts
	generations         map[string][]uint64
}

func (f *fakeNetworkRunner) Run(ctx context.Context, operation string, input []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operations = append(f.operations, operation)
	if f.generations == nil {
		f.generations = make(map[string][]uint64)
	}
	f.generations[operation] = append(f.generations[operation], traceevent.GenerationFromContext(ctx))
	if f.inputs == nil {
		f.inputs = make(map[string][]byte)
	}
	f.inputs[operation] = append([]byte(nil), input...)
	if f.inputHistory == nil {
		f.inputHistory = make(map[string][][]byte)
	}
	f.inputHistory[operation] = append(f.inputHistory[operation], append([]byte(nil), input...))
	if f.trace != nil {
		f.trace.record(operation)
	}
	if operation == networkOperationEmergency {
		f.emergencyContextErr = ctx.Err()
	}
	if queued := f.runErrors[operation]; len(queued) != 0 {
		err := queued[0]
		f.runErrors[operation] = queued[1:]
		return nil, err
	}
	if operation == networkOperationCapture {
		return json.Marshal(f.capture)
	}
	if operation == networkOperationReady {
		return json.Marshal(f.ready)
	}
	if operation == networkOperationResidue {
		return json.Marshal(f.residue)
	}
	if operation == networkOperationScan {
		f.scanCalls++
		if f.blockScanAfter > 0 && f.scanCalls >= f.blockScanAfter {
			f.scanStartOnce.Do(func() { close(f.scanStarted) })
			f.mu.Unlock()
			<-ctx.Done()
			f.mu.Lock()
			return nil, ctx.Err()
		}
		if len(f.scans) == 0 {
			return json.Marshal([]WindowsAdapterIdentity{{InterfaceIndex: 7, InterfaceGuid: "ethernet-guid", InterfaceAlias: "Ethernet", Status: "Up"}})
		}
		value := f.scans[0]
		if len(f.scans) > 1 {
			f.scans = f.scans[1:]
		}
		return json.Marshal(value)
	}
	if operation == networkOperationRestore && len(f.restoreErrors) != 0 {
		err := f.restoreErrors[0]
		f.restoreErrors = f.restoreErrors[1:]
		return nil, err
	}
	return nil, nil
}

func (f *fakeNetworkRunner) inputFor(t *testing.T, operation string) windowsNetworkInput {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var input windowsNetworkInput
	if err := json.Unmarshal(f.inputs[operation], &input); err != nil {
		t.Fatalf("decode %s input: %v", operation, err)
	}
	return input
}

func (f *fakeNetworkRunner) lastInputFor(t *testing.T, operation string) windowsNetworkInput {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	history := f.inputHistory[operation]
	if len(history) == 0 {
		t.Fatalf("no %s input", operation)
	}
	var input windowsNetworkInput
	if err := json.Unmarshal(history[len(history)-1], &input); err != nil {
		t.Fatalf("decode %s input: %v", operation, err)
	}
	return input
}

func (f *fakeNetworkRunner) count(operation string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, candidate := range f.operations {
		if candidate == operation {
			count++
		}
	}
	return count
}

func (f *fakeNetworkRunner) generationsFor(operation string) []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.generations[operation]...)
}

func waitForNetworkOperationCount(t *testing.T, runner *fakeNetworkRunner, operation string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runner.count(operation) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s operation count = %d, want at least %d", operation, runner.count(operation), want)
}

type fakeSnapshotStore struct {
	trace    *callTrace
	exists   bool
	snapshot WindowsNetworkSnapshot
}

func (f *fakeSnapshotStore) Save(_ string, snapshot WindowsNetworkSnapshot) error {
	f.exists = true
	f.snapshot = snapshot
	if f.trace != nil {
		f.trace.record("save")
	}
	return nil
}

func (f *fakeSnapshotStore) Load(string) (WindowsNetworkSnapshot, error) {
	if !f.exists {
		return WindowsNetworkSnapshot{}, errSnapshotNotFound
	}
	return f.snapshot, nil
}

func (f *fakeSnapshotStore) Delete(string) error {
	f.exists = false
	return nil
}
