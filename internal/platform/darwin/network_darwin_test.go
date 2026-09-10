//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamedTUNRouteIdentity(t *testing.T) {
	for _, tc := range []struct{ gateway, flags, iface, want string }{
		{"utun9", "UScg", "utun9", "link#19"},
		{"link#19", "UScg", "utun9", "link#19"},
		{"link#20", "UScg", "utun9", "link#20"},
		{"utun8", "UScg", "utun9", "utun8"},
		{"utun9", "UGSc", "utun9", "utun9"},
		{"172.19.0.1", "UGSc", "utun9", "172.19.0.1"},
	} {
		rows, err := parseRoutes("Destination Gateway Flags Netif\n0/1 "+tc.gateway+" "+tc.flags+" "+tc.iface+"\n", map[string]int{"utun9": 19})
		if err != nil || len(rows) != 1 || rows[0] != (ownedRoute{"0.0.0.0/1", tc.want, "utun9", 19}) {
			t.Fatalf("%+v: rows=%+v err=%v", tc, rows, err)
		}
	}
}

func TestDarwinRouteNotation(t *testing.T) {
	for _, tc := range []struct{ destination, flags, want string }{
		{"127", "UCS", "127.0.0.0/8"},
		{"169.254", "UCS", "169.254.0.0/16"},
		{"172.20", "UGSc", "172.20.0.0/16"},
		{"192.168.1", "UCS", "192.168.1.0/24"},
		{"172.20.20/22", "UCS", "172.20.20.0/22"},
		{"172.20.20.1", "UHLWIir", "172.20.20.1/32"},
		{"172.20.0.0", "UH", "172.20.0.0/32"},
		{"172.20.20.1/32", "UCS", "172.20.20.1/32"},
		{"0/1", "UCS", "0.0.0.0/1"},
		{"128/1", "UCS", "128.0.0.0/1"},
	} {
		t.Run(tc.destination+tc.flags, func(t *testing.T) {
			rows, e := parseRoutes("Destination Gateway Flags Netif Expire\n"+tc.destination+" link#4 "+tc.flags+" en0\n", map[string]int{"en0": 4})
			if e != nil {
				t.Fatal(e)
			}
			if len(rows) != 1 || rows[0].Destination != tc.want {
				t.Fatalf("parsed %v, want %s", rows, tc.want)
			}
		})
	}
}

// Model native netstat rendering at the network-system boundary: an owned
// management /16 is abbreviated, while the other routes retain CIDR output.
type abbreviatedRoutesSystem struct{ *fakeSystem }

func (s abbreviatedRoutesSystem) Routes(ctx context.Context) ([]ownedRoute, error) {
	routes, e := s.fakeSystem.Routes(ctx)
	if e != nil {
		return nil, e
	}
	var text strings.Builder
	text.WriteString("Destination Gateway Flags Netif Expire\n")
	indexes := map[string]int{}
	for _, r := range routes {
		destination := r.Destination
		if destination == "172.20.0.0/16" {
			destination = "172.20"
		}
		gateway, flags := r.Gateway, "UGSc"
		if r.Interface == TUNName && gateway == fmt.Sprintf("link#%d", r.Index) {
			gateway, flags = TUNName, "UScg"
		}
		fmt.Fprintf(&text, "%s %s %s %s\n", destination, gateway, flags, r.Interface)
		indexes[r.Interface] = r.Index
	}
	return parseRoutes(text.String(), indexes)
}

func TestAbbreviatedManagementRouteLifecycle(t *testing.T) {
	_, system, journal := fixture()
	manager := newNetworkManager(abbreviatedRoutesSystem{system}, journal)
	capture(t, manager)
	activate(t, manager, system)
	if len(system.routes) != 3 {
		t.Fatal("activation missing routes")
	}
	if e := manager.Restore(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	if len(system.routes) != 0 || journal.value != nil {
		t.Fatalf("owned management route survived restore: %+v", system.routes)
	}
}

func TestAbbreviatedManagementRouteConflict(t *testing.T) {
	_, system, journal := fixture()
	system.routes = []ownedRoute{{Destination: "172.20.0.0/16", Gateway: "172.20.20.1", Interface: "en0", Index: 4}}
	manager := newNetworkManager(abbreviatedRoutesSystem{system}, journal)
	if _, e := manager.Prepare(context.Background()); e == nil {
		t.Fatal("preexisting abbreviated management route accepted")
	}
	if system.changes != 0 {
		t.Fatal("preflight mutated network")
	}
}

func TestParseRoutes(t *testing.T) {
	v, e := parseRoutes("Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 172.20.20.1 UGScg en0\n0/1 link#12 UCS utun9\n172.20/16 172.20.20.1 UGSc en0\n", map[string]int{"en0": 4, "utun9": 12})
	if e != nil {
		t.Fatal(e)
	}
	if len(v) != 3 || v[1].Destination != "0.0.0.0/1" || v[2].Destination != "172.20.0.0/16" {
		t.Fatal(v)
	}
}
func TestParseServiceOrder(t *testing.T) {
	text := "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(2) USB LAN\n(Hardware Port: USB LAN, Device: en5)\n"
	s, e := parseService(text, "en0")
	if e != nil || s != "Wi-Fi" {
		t.Fatalf("%q %v", s, e)
	}
	if _, e = parseService(text+"(3) Duplicate\n(Hardware Port: Wi-Fi, Device: en0)\n", "en0"); e == nil {
		t.Fatal("ambiguous service accepted")
	}
}
func TestParseDNS(t *testing.T) {
	for _, text := range []string{"There aren't any DNS Servers set on Wi-Fi.\n", "172.20.9.1\n172.20.9.2\n"} {
		if _, e := parseDNS(text, "Wi-Fi"); e != nil {
			t.Fatal(e)
		}
	}
	for _, text := range []string{"error", "1.1.1.1\njunk", "There aren't any DNS Servers set on Ethernet."} {
		if _, e := parseDNS(text, "Wi-Fi"); e == nil {
			t.Fatal("ambiguous DNS accepted")
		}
	}
}
func TestJournalSecurityAndRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership journal test requires root")
	}
	dir := t.TempDir()
	var resolveErr error
	dir, resolveErr = filepath.EvalSymlinks(dir)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	j := fileJournal{directory: dir}
	s := &networkSnapshot{Version: 1, BootSession: "boot-1", Baseline: baseline{Interface: "en0", Index: 4, Gateway: "172.20.20.1", Service: "Wi-Fi"}}
	if e := j.Save(s); e != nil {
		t.Fatal(e)
	}
	if _, e := j.Load(); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(filepath.Join(dir, journalName), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := j.Load(); e == nil {
		t.Fatal("non-private journal accepted")
	}
}
