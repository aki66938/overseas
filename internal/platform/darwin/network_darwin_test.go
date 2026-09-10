//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"testing"
)

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
