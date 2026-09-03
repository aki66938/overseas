//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

var (
	dnsapi                    = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
)

// Minimal (PoC) routing: sing-box auto_route owns the routes and tun DNS,
// the product builds no firewall pool, owns no route table, and never
// touches physical adapter resolvers. Connect = start the core; disconnect
// = stop it and flush the resolver cache. Nothing is left behind to break.
type minimalRouting struct{}

func (minimalRouting) flushResolverCache() error {
	// Best-effort: the API may report failure for non-elevated callers; the
	// service (LocalSystem) flush succeeds and that is the path that matters.
	procDnsFlushResolverCache.Call()
	return nil
}

func (m *WindowsNetworkManager) preparePoc(ctx context.Context) (PreparedNetwork, error) {
	baseline, err := m.native.Baseline(ctx, m.nodeAddresses)
	if err != nil {
		return PreparedNetwork{}, fmt.Errorf("read network baseline: %w", err)
	}
	for _, adapter := range baseline.Adapters {
		if strings.EqualFold(adapter.InterfaceAlias, windowsTUNInterface) {
			return PreparedNetwork{}, errors.New("owned TUN alias exists while preparing")
		}
		if foreignTunnelAdapter(adapter) {
			return PreparedNetwork{}, fmt.Errorf("%w: %s (%s)", errVPNConflict, adapter.InterfaceAlias, adapter.Description)
		}
	}
	fingerprint, err := m.native.Fingerprint(ctx, m.nodeAddresses)
	if err != nil {
		return PreparedNetwork{}, err
	}
	adapterCount := 0
	for _, adapter := range baseline.Adapters {
		if !foreignTunnelAdapter(adapter) {
			adapterCount++
		}
	}
	state := WindowsPreparedState{
		Version: windowsPreparedStateVersion, Generation: 1,
		FingerprintSHA256: fingerprint, Baseline: baseline,
		RuleDefinitionVersion: windowsFirewallRuleDefinitionVersion,
	}
	state.AdapterCount = adapterCount
	result := preparedNetworkFromState(state)
	result.AdapterCount = adapterCount
	m.mu.Lock()
	m.prepared = &state
	m.mu.Unlock()
	return result, nil
}

func (m *WindowsNetworkManager) capturePoc(ctx context.Context, prepared PreparedNetwork) (any, error) {
	if err := validatePreparedNetwork(prepared); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.current != nil {
		m.mu.Unlock()
		return nil, errors.New("network state is already captured")
	}
	cached := m.prepared
	m.mu.Unlock()
	if cached == nil || cached.Generation != prepared.Generation {
		return nil, errors.New("prepared generation is stale")
	}
	state := *cached
	fingerprint, ferr := m.native.Fingerprint(ctx, m.nodeAddresses)
	if ferr != nil {
		return nil, ferr
	}
	if fingerprint != state.FingerprintSHA256 {
		return nil, errors.New("network fingerprint changed after preparation")
	}
	snapshot, serr := m.snapshotFromPrepared(state)
	if serr != nil {
		return nil, serr
	}
	m.mu.Lock()
	m.current = &snapshot
	m.mu.Unlock()
	return snapshot, nil
}
