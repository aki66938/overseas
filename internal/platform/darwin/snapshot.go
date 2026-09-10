package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"

	"corp.example/overseas-access-gateway/internal/agent"
)

const TUNName = "utun9"
const TUNAddress = "172.19.0.1/30"
const TUNDNS = "172.19.0.2"

type baseline struct {
	Interface string
	Index     int
	Gateway   string
	Service   string
	DNS       []string
}
type tunIdentity struct {
	Name    string
	Index   int
	Address string
}
type ownedRoute struct {
	Destination string
	Gateway     string
	Interface   string
	Index       int
}
type networkSnapshot struct {
	Version     int
	BootSession string
	Baseline    baseline
	TUN         tunIdentity
	Routes      []ownedRoute
	DNSIntended bool
}
type networkSystem interface {
	BootSession(context.Context) (string, error)
	Discover(context.Context) (baseline, error)
	TUN(context.Context) (tunIdentity, error)
	Routes(context.Context) ([]ownedRoute, error)
	DNS(context.Context, string) ([]string, error)
	SetDNS(context.Context, string, []string) error
	AddRoute(context.Context, ownedRoute) error
	DeleteRoute(context.Context, ownedRoute) error
}
type journal interface {
	Load() (*networkSnapshot, error)
	Save(*networkSnapshot) error
	Remove() error
}

// NetworkManager owns only explicit routes and the selected service's DNS.
// It provides no firewall enforcement or Windows fail-closed equivalence.
type NetworkManager struct {
	mu         sync.Mutex
	system     networkSystem
	journal    journal
	prepared   baseline
	generation uint64
	active     *networkSnapshot
	interval   time.Duration
}

var _ agent.NetworkManager = (*NetworkManager)(nil)

func newNetworkManager(s networkSystem, j journal) *NetworkManager {
	return &NetworkManager{system: s, journal: j, interval: 3 * time.Second}
}
func fingerprint(b baseline) string {
	v, _ := json.Marshal(b)
	return fmt.Sprintf("%x", sha256.Sum256(v))
}
func sameDNS(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func sameBaseline(a, b baseline) bool {
	return a.Interface == b.Interface && a.Index == b.Index && a.Gateway == b.Gateway && a.Service == b.Service && sameDNS(a.DNS, b.DNS)
}
func plannedDestination(d string) bool {
	return d == "0.0.0.0/1" || d == "128.0.0.0/1" || d == "172.20.0.0/16"
}
func (m *NetworkManager) preflight(ctx context.Context) (baseline, error) {
	b, e := m.system.Discover(ctx)
	if e != nil {
		return b, e
	}
	if b.Interface == "" || b.Index <= 0 || b.Gateway == "" || b.Service == "" {
		return b, errors.New("ambiguous physical network")
	}
	tun, e := m.system.TUN(ctx)
	if e != nil {
		return b, e
	}
	if tun.Name != "" {
		return b, errors.New("utun9 already exists")
	}
	routes, e := m.system.Routes(ctx)
	if e != nil {
		return b, e
	}
	for _, r := range routes {
		if plannedDestination(r.Destination) {
			return b, fmt.Errorf("route conflict: %s", r.Destination)
		}
		if strings.HasPrefix(r.Interface, "utun") {
			p, e := netip.ParsePrefix(r.Destination)
			if e != nil || !p.Addr().IsLinkLocalUnicast() {
				return b, errors.New("nonlocal foreign VPN route")
			}
		}
	}
	return b, nil
}
func (m *NetworkManager) Prepare(ctx context.Context) (agent.PreparedNetwork, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var p agent.PreparedNetwork
	s, e := m.journal.Load()
	if e != nil {
		return p, e
	}
	if s != nil || m.active != nil {
		return p, errors.New("unresolved network journal; reconcile required")
	}
	b, e := m.preflight(ctx)
	if e != nil {
		return p, e
	}
	m.generation++
	m.prepared = b
	return agent.PreparedNetwork{Generation: m.generation, Fingerprint: fingerprint(b), AdapterCount: 1}, nil
}
func (m *NetworkManager) Capture(ctx context.Context, p agent.PreparedNetwork) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != nil || p.Generation != m.generation || p.Generation == 0 {
		return nil, errors.New("stale network preparation")
	}
	existing, e := m.journal.Load()
	if e != nil {
		return nil, e
	}
	if existing != nil {
		return nil, errors.New("journal already exists")
	}
	b, e := m.preflight(ctx)
	if e != nil {
		return nil, e
	}
	if !sameBaseline(b, m.prepared) || p.Fingerprint != fingerprint(b) {
		return nil, errors.New("physical network changed before capture")
	}
	boot, e := m.system.BootSession(ctx)
	if e != nil {
		return nil, e
	}
	if boot == "" {
		return nil, errors.New("boot session unavailable")
	}
	s := &networkSnapshot{Version: 1, BootSession: boot, Baseline: b}
	if e = m.journal.Save(s); e != nil {
		return nil, e
	}
	m.active = s
	return s, nil
}
func (m *NetworkManager) EnableProtection(ctx context.Context, _ agent.PreparedNetwork) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return e
	}
	if m.active == nil {
		return errors.New("network not captured")
	}
	return nil
}
func (m *NetworkManager) WaitTUNReady(ctx context.Context) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		if m.active == nil {
			m.mu.Unlock()
			return errors.New("network not captured")
		}
		t, e := m.system.TUN(ctx)
		if e == nil && t.Name == TUNName && t.Index > 0 && t.Address == TUNAddress {
			snapshot := *m.active
			snapshot.TUN = t
			e = m.journal.Save(&snapshot)
			if e == nil {
				m.active = &snapshot
			}
			m.mu.Unlock()
			return e
		}
		m.mu.Unlock()
		if e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("TUN readiness timeout")
		case <-ticker.C:
		}
	}
}
func (m *NetworkManager) ActivateTUNRoutes(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.active
	if s == nil || s.TUN.Index <= 0 {
		return errors.New("captured TUN identity required")
	}
	t, e := m.system.TUN(ctx)
	if e != nil {
		return e
	}
	if t != s.TUN {
		return errors.New("TUN identity changed")
	}
	physical, e := m.system.Discover(ctx)
	if e != nil {
		return e
	}
	if !sameBaseline(physical, s.Baseline) {
		return errors.New("physical network changed before activation")
	}
	targets := []ownedRoute{{"172.20.0.0/16", s.Baseline.Gateway, s.Baseline.Interface, s.Baseline.Index}, {"0.0.0.0/1", fmt.Sprintf("link#%d", t.Index), TUNName, t.Index}, {"128.0.0.0/1", fmt.Sprintf("link#%d", t.Index), TUNName, t.Index}}
	for _, r := range targets {
		routes, e := m.system.Routes(ctx)
		if e != nil {
			return e
		}
		for _, v := range routes {
			if v.Destination == r.Destination {
				return fmt.Errorf("route conflict: %s", r.Destination)
			}
		}
		s.Routes = append(s.Routes, r)
		if e = m.journal.Save(s); e != nil {
			return e
		}
		if e = m.system.AddRoute(ctx, r); e != nil {
			return e
		}
	}
	dns, e := m.system.DNS(ctx, s.Baseline.Service)
	if e != nil {
		return e
	}
	if !sameDNS(dns, s.Baseline.DNS) {
		return errors.New("DNS changed before activation")
	}
	s.DNSIntended = true
	if e = m.journal.Save(s); e != nil {
		return e
	}
	return m.system.SetDNS(ctx, s.Baseline.Service, []string{TUNDNS})
}
func (m *NetworkManager) Restore(ctx context.Context, _ any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restore(ctx)
}
func (m *NetworkManager) restore(ctx context.Context) error {
	s := m.active
	if s == nil {
		var e error
		s, e = m.journal.Load()
		if e != nil {
			return e
		}
	}
	if s == nil {
		return nil
	}
	m.active = s
	var errs []error
	if s.DNSIntended {
		dns, e := m.system.DNS(ctx, s.Baseline.Service)
		if e != nil {
			errs = append(errs, e)
		} else if sameDNS(dns, s.Baseline.DNS) {
		} else if sameDNS(dns, []string{TUNDNS}) {
			if e = m.system.SetDNS(ctx, s.Baseline.Service, s.Baseline.DNS); e != nil {
				errs = append(errs, e)
			}
		} else {
			errs = append(errs, errors.New("DNS changed externally; needs action"))
		}
	}
	boot, bootErr := m.system.BootSession(ctx)
	for i := len(s.Routes) - 1; i >= 0; i-- {
		r := s.Routes[i]
		routes, e := m.system.Routes(ctx)
		if e != nil {
			errs = append(errs, e)
			continue
		}
		for _, v := range routes {
			if v.Destination != r.Destination {
				continue
			}
			if bootErr != nil || boot != s.BootSession {
				errs = append(errs, errors.New("route ownership cannot cross boot sessions; needs action"))
				continue
			}
			if v != r {
				errs = append(errs, fmt.Errorf("route %s changed externally; needs action", r.Destination))
				continue
			}
			if e = m.system.DeleteRoute(ctx, r); e != nil {
				errs = append(errs, e)
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if e := m.journal.Remove(); e != nil {
		return e
	}
	m.active = nil
	return nil
}
func (m *NetworkManager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restore(ctx)
}
func (m *NetworkManager) StartMonitor(ctx context.Context, p agent.PreparedNetwork) (<-chan error, error) {
	m.mu.Lock()
	if m.active == nil || p.Generation != m.generation {
		m.mu.Unlock()
		return nil, errors.New("no active network")
	}
	s := *m.active
	interval := m.interval
	m.mu.Unlock()
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			b, e := m.system.Discover(checkCtx)
			if e == nil {
				b.DNS = s.Baseline.DNS
				if !sameBaseline(b, s.Baseline) {
					e = errors.New("physical network changed")
				}
			}
			if e == nil {
				var t tunIdentity
				t, e = m.system.TUN(checkCtx)
				if e == nil && t != s.TUN {
					e = errors.New("TUN disappeared or changed")
				}
			}
			if e == nil {
				var dns []string
				dns, e = m.system.DNS(checkCtx, s.Baseline.Service)
				if e == nil && !reflect.DeepEqual(dns, []string{TUNDNS}) {
					e = errors.New("DNS changed")
				}
			}
			cancel()
			if e != nil {
				if ctx.Err() == nil {
					ch <- e
				}
				return
			}
		}
	}()
	return ch, nil
}
