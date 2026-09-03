//go:build windows

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"corp.example/overseas-access-gateway/internal/accessmodel"
	"golang.org/x/sys/windows"
)

const windowsPreparedStateFile = "prepared-network.json"

var errPreparedStateNotFound = errors.New("prepared network state not found")

type preparedStateStore interface {
	Save(string, WindowsPreparedState) error
	Load(string) (WindowsPreparedState, error)
	Delete(string) error
}

type prepareFlight struct {
	done   chan struct{}
	result PreparedNetwork
	err    error
}

type filePreparedStateStore struct{}

func (filePreparedStateStore) Save(path string, state WindowsPreparedState) error {
	contents, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".prepared-network-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(source, destination, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	keep = true
	return nil
}

func (filePreparedStateStore) Load(path string) (WindowsPreparedState, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return WindowsPreparedState{}, errPreparedStateNotFound
	}
	if err != nil {
		return WindowsPreparedState{}, err
	}
	var state WindowsPreparedState
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return WindowsPreparedState{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("prepared state contains trailing JSON")
		}
		return WindowsPreparedState{}, err
	}
	return state, nil
}

func (filePreparedStateStore) Delete(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func withWindowsPreparedStateStore(store preparedStateStore) WindowsNetworkOption {
	return func(manager *WindowsNetworkManager) { manager.preparedStore = store }
}

func (m *WindowsNetworkManager) Prepare(ctx context.Context) (PreparedNetwork, error) {
	if err := ctx.Err(); err != nil {
		return PreparedNetwork{}, err
	}
	m.mu.Lock()
	active := m.current != nil
	m.mu.Unlock()
	if active {
		return PreparedNetwork{}, errors.New("cannot prepare while a network transaction is active")
	}

	m.prepareMu.Lock()
	flight := m.prepareFlight
	if flight == nil {
		flight = &prepareFlight{done: make(chan struct{})}
		m.prepareFlight = flight
		workContext, cancelWork := context.WithTimeout(context.WithoutCancel(ctx), windowsPreparationTimeout)
		go func() {
			defer cancelWork()
			flight.result, flight.err = m.prepareNetwork(workContext)
			close(flight.done)
			m.prepareMu.Lock()
			if m.prepareFlight == flight {
				m.prepareFlight = nil
			}
			m.prepareMu.Unlock()
		}()
	}
	m.prepareMu.Unlock()

	select {
	case <-ctx.Done():
		return PreparedNetwork{}, ctx.Err()
	case <-flight.done:
		return flight.result, flight.err
	}
}

func (m *WindowsNetworkManager) prepareNetwork(ctx context.Context) (PreparedNetwork, error) {
	m.mu.Lock()
	if m.current != nil {
		m.mu.Unlock()
		return PreparedNetwork{}, errors.New("cannot prepare while a network transaction is active")
	}
	m.mu.Unlock()

	baseline, err := m.native.Baseline(ctx, m.nodeAddresses)
	if err != nil {
		return PreparedNetwork{}, fmt.Errorf("read prepared network baseline: %w", err)
	}
	for _, adapter := range baseline.Adapters {
		if strings.EqualFold(adapter.InterfaceAlias, windowsTUNInterface) {
			return PreparedNetwork{}, errors.New("owned TUN alias exists while preparing")
		}
		// Foreign tunnel adapters (Clash-family TUN, iKuuu/Sakura VPN, other
		// wintun/tap users) fight this product for the default egress and
		// churn the rule pool. Refuse with a clear, user-actionable error
		// instead of building rules around a transient topology.
		if foreignTunnelAdapter(adapter) {
			return PreparedNetwork{}, fmt.Errorf("%w: %s (%s)", errVPNConflict, adapter.InterfaceAlias, adapter.Description)
		}
	}
	fingerprint, err := fingerprintNativeNetwork(baseline)
	if err != nil {
		return PreparedNetwork{}, err
	}
	policyHash, err := windowsPolicySHA256(m.policy)
	if err != nil {
		return PreparedNetwork{}, err
	}
	rules, err := buildPreparedFirewallRules(baseline.Adapters, m.blockedPrefixes, m.dnsBlockedPrefixes)
	if err != nil {
		return PreparedNetwork{}, err
	}

	existing, loadErr := m.preparedStore.Load(m.preparedPath)
	if loadErr == nil {
		if err := validateWindowsPreparedState(existing); err != nil {
			return PreparedNetwork{}, fmt.Errorf("validate persisted prepared state: %w", err)
		}
		if existing.PolicySHA256 == policyHash && existing.RuleDefinitionVersion == windowsFirewallRuleDefinitionVersion && existing.FingerprintSHA256 == fingerprint {
			if err := validatePreparedFirewallOwnership(rules, existing.Rules); err != nil {
				return PreparedNetwork{}, err
			}
			// No audit on the reuse path: the sealed ledger plus the arm-time
			// bulk assertions already prove ownership, and a full audit costs
			// ~10s of PowerShell on every click.
			m.mu.Lock()
			copyState := existing
			m.prepared = &copyState
			m.mu.Unlock()
			return preparedNetworkFromState(existing), nil
		}
	} else if !errors.Is(loadErr, errPreparedStateNotFound) {
		return PreparedNetwork{}, loadErr
	}

	generation := uint64(1)
	if loadErr == nil {
		generation = existing.Generation + 1
		if generation == 0 {
			return PreparedNetwork{}, errors.New("prepared generation overflow")
		}
	}
	state := WindowsPreparedState{
		Version: windowsPreparedStateVersion, Generation: generation, PolicySHA256: policyHash,
		RuleDefinitionVersion: windowsFirewallRuleDefinitionVersion, FingerprintSHA256: fingerprint,
		Baseline: baseline, BlockedRemoteAddresses: append([]string(nil), m.blockedPrefixes...),
		DNSBlockedRemoteAddresses: append([]string(nil), m.dnsBlockedPrefixes...), Rules: rules,
	}
	if err := sealWindowsPreparedState(&state); err != nil {
		return PreparedNetwork{}, err
	}
	if loadErr == nil {
		err = m.prepareFirewallPool(ctx, state, existing)
	} else {
		err = m.prepareFirewallPool(ctx, state)
	}
	if err != nil {
		return PreparedNetwork{}, err
	}
	if err := m.auditPreparedFirewall(ctx, state, false); err != nil {
		return PreparedNetwork{}, errors.Join(err, m.installPreparedEmergencyProtection(ctx, state))
	}
	if err := m.preparedStore.Save(m.preparedPath, state); err != nil {
		publishErr := fmt.Errorf("publish prepared network state: %w", err)
		if loadErr == nil {
			rollbackContext, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), windowsPreparationTimeout)
			defer cancelRollback()
			return PreparedNetwork{}, errors.Join(publishErr, m.prepareFirewallPool(rollbackContext, existing, state))
		}
		return PreparedNetwork{}, publishErr
	}
	m.mu.Lock()
	copyState := state
	m.prepared = &copyState
	m.mu.Unlock()
	return preparedNetworkFromState(state), nil
}

func windowsPolicySHA256(policy accessmodel.Policy) (string, error) {
	copyPolicy := clonePolicy(policy)
	sort.Slice(copyPolicy.Nodes, func(i, j int) bool {
		if copyPolicy.Nodes[i].Priority != copyPolicy.Nodes[j].Priority {
			return copyPolicy.Nodes[i].Priority < copyPolicy.Nodes[j].Priority
		}
		return copyPolicy.Nodes[i].ID < copyPolicy.Nodes[j].ID
	})
	sort.Strings(copyPolicy.CorporateCIDRs)
	sort.Strings(copyPolicy.CorporateDNS)
	sort.Strings(copyPolicy.InternalSuffixes)
	payload, err := json.Marshal(copyPolicy)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(payload)), nil
}

func preparedNetworkFromState(state WindowsPreparedState) PreparedNetwork {
	adapterCount := 0
	for _, rule := range state.Rules {
		if rule.InterfaceGuid != "" && !rule.Emergency {
			adapterCount++
		}
	}
	return PreparedNetwork{Generation: state.Generation, Fingerprint: state.FingerprintSHA256, AdapterCount: adapterCount, RuleCount: len(state.Rules)}
}

func (m *WindowsNetworkManager) capturePrepared(ctx context.Context, prepared PreparedNetwork) (any, error) {
	if err := validatePreparedNetwork(prepared); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		return nil, errors.New("network state is already captured")
	}
	state, err := m.preparedStore.Load(m.preparedPath)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsPreparedState(state); err != nil {
		return nil, err
	}
	if preparedNetworkFromState(state) != prepared {
		return nil, errors.New("prepared generation is stale")
	}
	fingerprint, err := m.native.Fingerprint(ctx, m.nodeAddresses)
	if err != nil {
		return nil, err
	}
	if fingerprint != state.FingerprintSHA256 {
		return nil, errors.New("network fingerprint changed after preparation")
	}
	if _, err := m.store.Load(m.statePath); err == nil {
		return nil, errors.New("unreconciled network snapshot exists")
	} else if !errors.Is(err, errSnapshotNotFound) {
		return nil, err
	}
	snapshot, err := m.snapshotFromPrepared(state)
	if err != nil {
		return nil, err
	}
	if err := sealWindowsSnapshot(&snapshot); err != nil {
		return nil, err
	}
	if err := m.validateWindowsSnapshot(snapshot); err != nil {
		return nil, err
	}
	if err := m.store.Save(m.statePath, snapshot); err != nil {
		return nil, err
	}
	m.current = &snapshot
	copyState := state
	m.prepared = &copyState
	return snapshot, nil
}

func (m *WindowsNetworkManager) snapshotFromPrepared(state WindowsPreparedState) (WindowsNetworkSnapshot, error) {
	metrics := make(map[int]WindowsNativeInterface, len(state.Baseline.Interfaces))
	for _, metric := range state.Baseline.Interfaces {
		metrics[metric.InterfaceIndex] = metric
	}
	interfaces := make([]WindowsInterfaceSnapshot, 0, len(state.Baseline.Adapters))
	guids := make([]string, 0, len(state.Baseline.Adapters))
	for _, adapter := range state.Baseline.Adapters {
		guids = append(guids, adapter.InterfaceGuid)
		if adapter.InterfaceIndex == 1 || strings.EqualFold(adapter.Status, "NotPresent") {
			continue
		}
		metric, ok := metrics[adapter.InterfaceIndex]
		if !ok || (metric.InterfaceLUID != 0 && adapter.InterfaceLUID != 0 && metric.InterfaceLUID != adapter.InterfaceLUID) {
			return WindowsNetworkSnapshot{}, errors.New("prepared adapter metric identity is incomplete")
		}
		interfaces = append(interfaces, WindowsInterfaceSnapshot{
			Index: adapter.InterfaceIndex, InterfaceGuid: adapter.InterfaceGuid, Alias: adapter.InterfaceAlias,
			InterfaceMetric: metric.InterfaceMetric, AutomaticMetric: metric.AutomaticMetric,
			DNSAutomatic: adapter.DNSAutomatic, DNSServers: append([]string(nil), adapter.DNSServers...),
		})
	}
	sort.Strings(guids)
	return WindowsNetworkSnapshot{
		Version: 1, Interfaces: interfaces, BaselineAdapterGuids: guids,
		NodeRoutes:                append([]WindowsNodeRouteSnapshot(nil), state.Baseline.NodeRoutes...),
		BlockedRemoteAddresses:    append([]string(nil), m.blockedPrefixes...),
		DNSBlockedRemoteAddresses: append([]string(nil), m.dnsBlockedPrefixes...),
		RouteMetric:               windowsOwnedRouteMetric, OwnershipPhase: windowsSnapshotPhaseCaptured,
		PreparedGeneration: state.Generation,
	}, nil
}

func (m *WindowsNetworkManager) EnableProtection(ctx context.Context, prepared PreparedNetwork) error {
	m.mu.Lock()
	if m.current == nil || m.current.PreparedGeneration != prepared.Generation || m.prepared == nil || preparedNetworkFromState(*m.prepared) != prepared {
		m.mu.Unlock()
		return errors.New("active snapshot does not match prepared generation")
	}
	state := *m.prepared
	m.current.OwnershipPhase = windowsSnapshotPhaseProtected
	if err := sealWindowsSnapshot(m.current); err != nil {
		m.mu.Unlock()
		return err
	}
	if err := m.store.Save(m.statePath, *m.current); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	if err := m.armPreparedFirewall(ctx, state); err != nil {
		return errors.Join(err, m.installPreparedEmergencyProtection(context.WithoutCancel(ctx), state))
	}
	return nil
}
