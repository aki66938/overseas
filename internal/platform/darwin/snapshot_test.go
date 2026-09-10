package darwin

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memoryJournal struct {
	value *networkSnapshot
	fail  bool
}

func (j *memoryJournal) Load() (*networkSnapshot, error) { return j.value, nil }
func (j *memoryJournal) Save(s *networkSnapshot) error {
	if j.fail {
		return errors.New("disk failed")
	}
	copy := *s
	copy.Routes = append([]ownedRoute(nil), s.Routes...)
	j.value = &copy
	return nil
}
func (j *memoryJournal) Remove() error { j.value = nil; return nil }

type fakeSystem struct {
	base    baseline
	tun     tunIdentity
	routes  []ownedRoute
	dns     []string
	changes int
	failAdd int
	failDNS bool
	boot    string
}

func (s *fakeSystem) BootSession(context.Context) (string, error) {
	if s.boot == "" {
		return "boot-1", nil
	}
	return s.boot, nil
}

func (s *fakeSystem) Discover(context.Context) (baseline, error) {
	b := s.base
	b.DNS = append([]string(nil), s.dns...)
	return b, nil
}
func (s *fakeSystem) TUN(context.Context) (tunIdentity, error) { return s.tun, nil }
func (s *fakeSystem) Routes(context.Context) ([]ownedRoute, error) {
	return append([]ownedRoute(nil), s.routes...), nil
}
func (s *fakeSystem) DNS(context.Context, string) ([]string, error) {
	return append([]string(nil), s.dns...), nil
}
func (s *fakeSystem) SetDNS(_ context.Context, _ string, v []string) error {
	s.changes++
	if s.failDNS {
		return errors.New("DNS failed")
	}
	s.dns = append([]string(nil), v...)
	return nil
}
func (s *fakeSystem) AddRoute(_ context.Context, r ownedRoute) error {
	s.changes++
	if s.failAdd == s.changes {
		return errors.New("add failed")
	}
	s.routes = append(s.routes, r)
	return nil
}
func (s *fakeSystem) DeleteRoute(_ context.Context, r ownedRoute) error {
	s.changes++
	for i, v := range s.routes {
		if v == r {
			s.routes = append(s.routes[:i], s.routes[i+1:]...)
			return nil
		}
	}
	return nil
}
func fixture() (*NetworkManager, *fakeSystem, *memoryJournal) {
	s := &fakeSystem{base: baseline{Interface: "en0", Index: 4, Gateway: "172.20.20.1", Service: "Wi-Fi"}, dns: []string{"172.20.9.1"}}
	j := &memoryJournal{}
	return newNetworkManager(s, j), s, j
}
func capture(t *testing.T, m *NetworkManager) {
	t.Helper()
	p, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Capture(context.Background(), p); e != nil {
		t.Fatal(e)
	}
}
func activate(t *testing.T, m *NetworkManager, s *fakeSystem) {
	t.Helper()
	s.tun = tunIdentity{Name: TUNName, Index: 12, Address: TUNAddress}
	if e := m.WaitTUNReady(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := m.ActivateTUNRoutes(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestCaptureMustPersistBeforeMutation(t *testing.T) {
	m, s, j := fixture()
	p, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	j.fail = true
	if _, e = m.Capture(context.Background(), p); e == nil {
		t.Fatal("disk failure accepted")
	}
	if e = m.ActivateTUNRoutes(context.Background()); e == nil {
		t.Fatal("uncaptured activation accepted")
	}
	if s.changes != 0 {
		t.Fatal("mutated before journal")
	}
}
func TestDNSRoundTrip(t *testing.T) {
	for _, dns := range [][]string{nil, {"172.20.9.1", "172.20.9.2"}} {
		m, s, j := fixture()
		s.dns = dns
		capture(t, m)
		activate(t, m, s)
		if e := m.Restore(context.Background(), nil); e != nil {
			t.Fatal(e)
		}
		if !sameDNS(s.dns, dns) || len(s.routes) != 0 || j.value != nil {
			t.Fatal("roundtrip residue")
		}
		if e := m.Restore(context.Background(), nil); e != nil {
			t.Fatal(e)
		}
	}
}
func TestPartialActivationRestores(t *testing.T) {
	m, s, j := fixture()
	capture(t, m)
	s.tun = tunIdentity{Name: TUNName, Index: 12, Address: TUNAddress}
	if e := m.WaitTUNReady(context.Background()); e != nil {
		t.Fatal(e)
	}
	s.failAdd = 2
	if e := m.ActivateTUNRoutes(context.Background()); e == nil {
		t.Fatal("expected failure")
	}
	if e := m.Restore(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	if len(s.routes) != 0 || j.value != nil {
		t.Fatal("residue")
	}
}
func TestForeignDNSPreservedAndJournalRetained(t *testing.T) {
	m, s, j := fixture()
	capture(t, m)
	activate(t, m, s)
	s.dns = []string{"1.1.1.1"}
	if e := m.Restore(context.Background(), nil); e == nil {
		t.Fatal("foreign change hidden")
	}
	if s.dns[0] != "1.1.1.1" || j.value == nil {
		t.Fatal("foreign change lost")
	}
	if _, e := m.Prepare(context.Background()); e == nil {
		t.Fatal("new connection accepted")
	}
}
func TestForeignRoutePreserved(t *testing.T) {
	m, s, j := fixture()
	capture(t, m)
	activate(t, m, s)
	s.routes[1].Index = 99
	if e := m.Restore(context.Background(), nil); e == nil {
		t.Fatal("foreign route hidden")
	}
	if len(s.routes) != 1 || s.routes[0].Index != 99 || j.value == nil {
		t.Fatal("foreign route deleted")
	}
}
func TestReconcileRetainsJournalOnRestoreFailure(t *testing.T) {
	m, s, j := fixture()
	capture(t, m)
	activate(t, m, s)
	s.failDNS = true
	m = newNetworkManager(s, j)
	if e := m.Reconcile(context.Background()); e == nil || j.value == nil {
		t.Fatal("failed recovery discarded")
	}
	s.failDNS = false
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestPreexistingTUNAndRoutesRejected(t *testing.T) {
	m, s, _ := fixture()
	s.tun = tunIdentity{Name: TUNName, Index: 12, Address: TUNAddress}
	if _, e := m.Prepare(context.Background()); e == nil {
		t.Fatal("foreign tun accepted")
	}
	s.tun = tunIdentity{}
	s.routes = []ownedRoute{{Destination: "0.0.0.0/1"}}
	if _, e := m.Prepare(context.Background()); e == nil {
		t.Fatal("conflicting route accepted")
	}
}
func TestForeignVPNRouteRejected(t *testing.T) {
	m, s, _ := fixture()
	s.routes = []ownedRoute{{Destination: "8.8.8.8/32", Interface: "utun3", Index: 7}}
	if _, e := m.Prepare(context.Background()); e == nil {
		t.Fatal("nonlocal VPN route accepted")
	}
	s.routes[0].Destination = "169.254.0.0/16"
	if _, e := m.Prepare(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestActivationRevalidatesPhysicalNetwork(t *testing.T) {
	m, s, _ := fixture()
	capture(t, m)
	s.tun = tunIdentity{Name: TUNName, Index: 12, Address: TUNAddress}
	if e := m.WaitTUNReady(context.Background()); e != nil {
		t.Fatal(e)
	}
	s.base.Gateway = "172.20.20.2"
	if e := m.ActivateTUNRoutes(context.Background()); e == nil {
		t.Fatal("changed physical route accepted")
	}
	if s.changes != 0 {
		t.Fatal("mutated changed physical network")
	}
}

func TestRebootPreservesPresentRoutes(t *testing.T) {
	m, s, j := fixture()
	capture(t, m)
	activate(t, m, s)
	s.boot = "boot-2"
	m = newNetworkManager(s, j)
	if e := m.Reconcile(context.Background()); e == nil {
		t.Fatal("cross-boot ownership guessed")
	}
	if len(s.routes) != 3 || j.value == nil {
		t.Fatal("cross-boot routes deleted")
	}
	s.routes = nil
	if e := m.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	if j.value != nil {
		t.Fatal("missing cross-boot routes left residue")
	}
}

func TestFailedTUNJournalCannotActivate(t *testing.T) {
	m, s, j := fixture()
	capture(t, m)
	s.tun = tunIdentity{Name: TUNName, Index: 12, Address: TUNAddress}
	j.fail = true
	if e := m.WaitTUNReady(context.Background()); e == nil {
		t.Fatal("journal failure accepted")
	}
	j.fail = false
	if e := m.ActivateTUNRoutes(context.Background()); e == nil {
		t.Fatal("undurable TUN identity accepted")
	}
	if s.changes != 0 {
		t.Fatal("mutated without durable TUN identity")
	}
}
func TestMonitorDetectsChangesAndCancellation(t *testing.T) {
	for _, kind := range []string{"physical", "tun", "dns", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			m, s, _ := fixture()
			p, e := m.Prepare(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = m.Capture(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			activate(t, m, s)
			m.interval = time.Millisecond
			switch kind {
			case "physical":
				s.base.Gateway = "172.20.20.2"
			case "tun":
				s.tun.Index++
			case "dns":
				s.dns = nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				cancel()
			}
			ch, e := m.StartMonitor(ctx, p)
			if e != nil {
				t.Fatal(e)
			}
			select {
			case e, ok := <-ch:
				if kind == "cancel" {
					if ok {
						t.Fatal("cancellation emitted failure")
					}
				} else if !ok || e == nil {
					t.Fatal("change not detected")
				}
			case <-time.After(time.Second):
				t.Fatal("monitor hung")
			}
		})
	}
}
