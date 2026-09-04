//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dnsapi                      = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache   = dnsapi.NewProc("DnsFlushResolverCache")
	procSetInterfaceDnsSettings = iphlpapi.NewProc("SetInterfaceDnsSettings")
)

const (
	dnsInterfaceSettingsVersion1 = 1
	dnsSettingNameserver         = 0x0001
)

type dnsInterfaceSettings struct {
	Version    uint32
	Flags      uint32
	Domain     *uint16
	NameServer *uint16
}

// setInterfaceDNS points one interface (GUID with braces) at servers; an
// empty string returns it to automatic (DHCP) resolution.
func setInterfaceDNS(interfaceGuid, servers string) error {
	name, err := windows.UTF16PtrFromString(interfaceGuid)
	if err != nil {
		return err
	}
	var serverPtr *uint16
	if servers != "" {
		if serverPtr, err = windows.UTF16PtrFromString(servers); err != nil {
			return err
		}
	}
	settings := dnsInterfaceSettings{
		Version:    dnsInterfaceSettingsVersion1,
		Flags:      dnsSettingNameserver,
		NameServer: serverPtr,
	}
	result, _, _ := procSetInterfaceDnsSettings.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&settings)),
	)
	if result != 0 {
		return fmt.Errorf("SetInterfaceDnsSettings(%s): winerror %d", interfaceGuid, result)
	}
	return nil
}

type adapterLister interface {
	Adapters(context.Context) ([]ipHelperAdapter, error)
}

// pointAllResolversAtTun aims every live IPv4 interface's resolver at the
// tun resolver natively — no WMI, no PowerShell, no racing with the core's
// own route setup.
func (m *WindowsNetworkManager) pointAllResolversAtTun(ctx context.Context) error {
	lister, ok := m.native.(adapterLister)
	if !ok {
		return errors.New("native adapter listing is unavailable")
	}
	adapters, err := lister.Adapters(ctx)
	if err != nil {
		return err
	}
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.InterfaceAlias, windowsTUNInterface) {
			continue
		}
		if err := setInterfaceDNS(adapter.InterfaceGuid, windowsTUNDNS); err != nil {
			return err
		}
	}
	tunGuid := ""
	if m.currentGuidLocked(&tunGuid); tunGuid != "" {
		return setInterfaceDNS(tunGuid, windowsTUNDNS)
	}
	return nil
}

// restoreSnapshotResolvers returns each captured interface to its original
// resolver configuration (captured static list, or automatic when it was
// automatic) and resets any straggler still pointing at the tun resolver.
func (m *WindowsNetworkManager) restoreSnapshotResolvers(ctx context.Context) error {
	lister, ok := m.native.(adapterLister)
	if !ok {
		return errors.New("native adapter listing is unavailable")
	}
	adapters, err := lister.Adapters(ctx)
	if err != nil {
		return err
	}
	snapshotServers := make(map[string]string)
	m.mu.Lock()
	if m.current != nil {
		for _, iface := range m.current.Interfaces {
			if iface.DNSAutomatic {
				snapshotServers[canonicalGuid(iface.InterfaceGuid)] = ""
			} else {
				snapshotServers[canonicalGuid(iface.InterfaceGuid)] = strings.Join(iface.DNSServers, ",")
			}
		}
	}
	m.mu.Unlock()
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.InterfaceAlias, windowsTUNInterface) {
			continue
		}
		key := canonicalGuid(adapter.InterfaceGuid)
		if servers, captured := snapshotServers[key]; captured {
			if err := setInterfaceDNS(adapter.InterfaceGuid, servers); err != nil {
				return err
			}
			continue
		}
		// not in the snapshot but still pointing at the tun resolver — reset
		if resolverListHasServer(adapter.DNSServers, windowsTUNDNS) {
			if err := setInterfaceDNS(adapter.InterfaceGuid, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func canonicalGuid(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func resolverListHasServer(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

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
	if err := m.recoverOwnedPhantomTUN(ctx); err != nil {
		return PreparedNetwork{}, err
	}
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

func (m *WindowsNetworkManager) recoverOwnedPhantomTUN(ctx context.Context) error {
	_, err := m.run(ctx, networkOperationTUNRecover, windowsNetworkInput{
		TUNInterface:   windowsTUNInterface,
		CoreExecutable: windowsCoreExecutable,
	})
	return err
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

func (m *WindowsNetworkManager) currentGuidLocked(out *string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil && m.current.OwnedTUN != nil {
		*out = m.current.OwnedTUN.InterfaceGuid
	}
}
