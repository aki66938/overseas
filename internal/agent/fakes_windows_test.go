//go:build windows

package agent

import (
	"context"
	"errors"
	"sync"

	"corp.example/overseas-access-gateway/internal/traceevent"
)

// Minimal fakes for the PoC fast path: the manager no longer shells out on
// the connect path, so a do-nothing runner suffices.
type fakeNetworkRunner struct {
	mu         sync.Mutex
	ops        []string
	residue    traceevent.Residue
	residueErr error
}

func (f *fakeNetworkRunner) Run(_ context.Context, operation string, _ []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, operation)
	return []byte(`{}`), nil
}

type fakeSnapshotStore struct{}

func (fakeSnapshotStore) Save(string, WindowsNetworkSnapshot) error { return nil }
func (fakeSnapshotStore) Load(string) (WindowsNetworkSnapshot, error) {
	return WindowsNetworkSnapshot{}, errSnapshotNotFound
}
func (fakeSnapshotStore) Delete(string) error { return nil }

// scriptedNativeReader replays baselines and fingerprints and reports a
// scripted TUN identity.
type scriptedNativeReader struct {
	mu        sync.Mutex
	baselines []WindowsNetworkBaseline
	calls     int
	tun       WindowsTUNIdentity
	tunReady  bool
}

func (r *scriptedNativeReader) Baseline(_ context.Context, _ []string) (WindowsNetworkBaseline, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if len(r.baselines) == 0 {
		return WindowsNetworkBaseline{}, errors.New("no scripted baseline")
	}
	value := r.baselines[0]
	if len(r.baselines) > 1 {
		r.baselines = r.baselines[1:]
	}
	return value, nil
}

func (r *scriptedNativeReader) Fingerprint(ctx context.Context, nodes []string) (string, error) {
	baseline, err := r.Baseline(ctx, nodes)
	if err != nil {
		return "", err
	}
	return fingerprintNativeNetwork(baseline)
}

func (r *scriptedNativeReader) Adapters(_ context.Context) ([]ipHelperAdapter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.baselines) == 0 {
		return nil, errors.New("no scripted baseline")
	}
	adapters := make([]ipHelperAdapter, 0, len(r.baselines[0].Adapters))
	for _, adapter := range r.baselines[0].Adapters {
		adapters = append(adapters, ipHelperAdapter{
			InterfaceIndex: adapter.InterfaceIndex, InterfaceGuid: adapter.InterfaceGuid,
			InterfaceAlias: adapter.InterfaceAlias, Status: adapter.Status,
			DNSServers: adapter.DNSServers, DNSAutomatic: adapter.DNSAutomatic,
		})
	}
	return adapters, nil
}

func (r *scriptedNativeReader) TUNReady(_ context.Context, alias, address string, _ []string) (WindowsTUNIdentity, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tun, r.tunReady, nil
}

func validPreparedBaseline() WindowsNetworkBaseline {
	return WindowsNetworkBaseline{
		Adapters:   []WindowsNativeAdapter{{InterfaceIndex: 4, InterfaceLUID: 44, InterfaceGuid: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", InterfaceAlias: "Ethernet", Status: "Up", DNSServers: []string{"172.20.9.1", "172.20.9.2"}, DNSAutomatic: true}},
		Interfaces: []WindowsNativeInterface{{InterfaceIndex: 4, InterfaceLUID: 44, AutomaticMetric: true, InterfaceMetric: 25}},
		Routes:     []WindowsNativeRoute{{DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, InterfaceLUID: 44, NextHop: "172.20.10.1", RouteMetric: 0, Protocol: 3}},
		NodeRoutes: []WindowsNodeRouteSnapshot{{NodeAddress: "172.20.9.15", DestinationPrefix: "0.0.0.0/0", InterfaceIndex: 4, NextHop: "172.20.10.1", RouteMetric: 0, InterfaceMetric: 25, EffectiveMetric: 25, BypassRequired: true}},
	}
}

func validTUNIdentity() WindowsTUNIdentity {
	return WindowsTUNIdentity{
		InterfaceIndex: 41, InterfaceGuid: "new-tun-guid", InterfaceAlias: windowsTUNInterface,
		Addresses: []string{windowsTUNAddress},
	}
}
