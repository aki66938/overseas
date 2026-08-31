package accessmodel_test

import (
	"regexp"
	"testing"

	"corp.example/overseas-access-gateway/internal/accessmodel"
)

func TestValidatePoCPolicy(t *testing.T) {
	p := accessmodel.Policy{
		SchemaVersion: 1,
		Mode:          "poc",
		Nodes: []accessmodel.Node{{
			ID:      "vm101",
			Address: "172.20.9.15",
			Port:    18443,
		}},
		CorporateCIDRs: []string{"172.20.8.0/22"},
		BlockUDP:       true,
		BlockQUIC:      true,
		Credential: accessmodel.CredentialRef{
			Kind: "dpapi-file",
			Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`,
		},
	}

	if err := accessmodel.Validate(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDirectHTTPPolicy(t *testing.T) {
	p := accessmodel.Policy{
		SchemaVersion: 2,
		Mode:          "poc",
		Nodes: []accessmodel.Node{{
			ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080,
		}},
		CorporateCIDRs: []string{"172.20.8.0/22"},
		CorporateDNS:   []string{"172.20.9.1"},
		BlockUDP:       true,
		BlockQUIC:      true,
	}

	if err := accessmodel.Validate(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDirectHTTPPolicyRejectsUnapprovedTransportEndpointOrCredential(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*accessmodel.Policy)
	}{
		{name: "empty transport", mutate: func(p *accessmodel.Policy) { p.Nodes[0].Transport = "" }},
		{name: "shadowsocks", mutate: func(p *accessmodel.Policy) { p.Nodes[0].Transport = "shadowsocks" }},
		{name: "loopback", mutate: func(p *accessmodel.Policy) { p.Nodes[0].Address = "127.0.0.1" }},
		{name: "wildcard", mutate: func(p *accessmodel.Policy) { p.Nodes[0].Address = "0.0.0.0" }},
		{name: "other address", mutate: func(p *accessmodel.Policy) { p.Nodes[0].Address = "172.20.9.16" }},
		{name: "other port", mutate: func(p *accessmodel.Policy) { p.Nodes[0].Port = 18443 }},
		{name: "credential", mutate: func(p *accessmodel.Policy) {
			p.Credential = accessmodel.CredentialRef{Kind: "dpapi-file", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := validDirectHTTPPolicy()
			test.mutate(&p)
			if err := accessmodel.Validate(p); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRejectsUnsafePolicy(t *testing.T) {
	cases := []accessmodel.Policy{
		{SchemaVersion: 1, Mode: "poc", Nodes: nil},
		{
			SchemaVersion:  1,
			Mode:           "poc",
			Nodes:          []accessmodel.Node{{ID: "vm101", Address: "172.20.9.15", Port: 18443}},
			CorporateCIDRs: []string{"0.0.0.0/0"},
			BlockUDP:       true,
			BlockQUIC:      true,
			Credential:     accessmodel.CredentialRef{Kind: "dpapi-file", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`},
		},
		{
			SchemaVersion: 1,
			Mode:          "poc",
			Nodes:         []accessmodel.Node{{ID: "vm101", Address: "127.0.0.1", Port: 18443}},
			BlockUDP:      true,
			BlockQUIC:     true,
			Credential:    accessmodel.CredentialRef{Kind: "dpapi-file", Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`},
		},
	}

	for i, p := range cases {
		if accessmodel.Validate(p) == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestValidateRejectsUnknownSchemaModeAndUnsafeFlags(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*accessmodel.Policy)
	}{
		{name: "schema version", mutate: func(p *accessmodel.Policy) { p.SchemaVersion = 2 }},
		{name: "mode", mutate: func(p *accessmodel.Policy) { p.Mode = "prod" }},
		{name: "block udp", mutate: func(p *accessmodel.Policy) { p.BlockUDP = false }},
		{name: "block quic", mutate: func(p *accessmodel.Policy) { p.BlockQUIC = false }},
		{name: "credential path", mutate: func(p *accessmodel.Policy) { p.Credential.Path = `credential.bin` }},
		{name: "credential kind", mutate: func(p *accessmodel.Policy) { p.Credential.Kind = "" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := validPolicy()
			test.mutate(&p)

			if err := accessmodel.Validate(p); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateRejectsDuplicateNodesAndReservedPorts(t *testing.T) {
	tests := []struct {
		name  string
		nodes []accessmodel.Node
	}{
		{
			name:  "duplicate id",
			nodes: []accessmodel.Node{{ID: "vm101", Address: "172.20.9.15", Port: 18443}, {ID: "vm101", Address: "172.20.9.16", Port: 18444}},
		},
		{
			name:  "duplicate endpoint",
			nodes: []accessmodel.Node{{ID: "vm101", Address: "172.20.9.15", Port: 18443}, {ID: "vm102", Address: "172.20.9.15", Port: 18443}},
		},
		{
			name:  "reserved port",
			nodes: []accessmodel.Node{{ID: "vm101", Address: "172.20.9.15", Port: 443}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := validPolicy()
			p.Nodes = test.nodes

			if err := accessmodel.Validate(p); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCanonicalSHA256IsStableAndOrderIndependent(t *testing.T) {
	first := validPolicy()
	first.Nodes = []accessmodel.Node{
		{ID: "vm102", Address: "172.20.9.16", Port: 18444, Priority: 20},
		{ID: "vm101", Address: "172.20.9.15", Port: 18443, Priority: 10},
	}
	first.CorporateCIDRs = []string{"172.20.9.0/24", "172.20.8.0/24"}
	first.CorporateDNS = []string{"172.20.10.2", "172.20.10.1"}
	first.InternalSuffixes = []string{"svc.intra.regen-bio.com", "ad.intra.regen-bio.com"}

	second := validPolicy()
	second.Nodes = []accessmodel.Node{
		{ID: "vm101", Address: "172.20.9.15", Port: 18443, Priority: 10},
		{ID: "vm102", Address: "172.20.9.16", Port: 18444, Priority: 20},
	}
	second.CorporateCIDRs = []string{"172.20.8.0/24", "172.20.9.0/24"}
	second.CorporateDNS = []string{"172.20.10.1", "172.20.10.2"}
	second.InternalSuffixes = []string{"ad.intra.regen-bio.com", "svc.intra.regen-bio.com"}

	firstHash, err := accessmodel.CanonicalSHA256(first)
	if err != nil {
		t.Fatalf("CanonicalSHA256(first) error: %v", err)
	}
	secondHash, err := accessmodel.CanonicalSHA256(second)
	if err != nil {
		t.Fatalf("CanonicalSHA256(second) error: %v", err)
	}

	if firstHash != secondHash {
		t.Fatalf("hashes differ: %q vs %q", firstHash, secondHash)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(firstHash) {
		t.Fatalf("hash = %q, want lowercase SHA-256", firstHash)
	}
}

func validPolicy() accessmodel.Policy {
	return accessmodel.Policy{
		SchemaVersion: 1,
		Mode:          "poc",
		Nodes: []accessmodel.Node{{
			ID:       "vm101",
			Address:  "172.20.9.15",
			Port:     18443,
			Priority: 10,
		}},
		CorporateCIDRs:   []string{"172.20.8.0/22"},
		CorporateDNS:     []string{"172.20.10.1"},
		InternalSuffixes: []string{"ad.intra.regen-bio.com"},
		BlockUDP:         true,
		BlockQUIC:        true,
		Credential: accessmodel.CredentialRef{
			Kind: "dpapi-file",
			Path: `C:\ProgramData\RegenBio\OverseasAccess\credential.bin`,
		},
	}
}

func validDirectHTTPPolicy() accessmodel.Policy {
	return accessmodel.Policy{
		SchemaVersion: 2,
		Mode:          "poc",
		Nodes: []accessmodel.Node{{
			ID: "vm101", Transport: "http-connect", Address: "172.20.9.15", Port: 8080, Priority: 10,
		}},
		CorporateCIDRs:   []string{"172.20.8.0/22"},
		CorporateDNS:     []string{"172.20.9.1"},
		InternalSuffixes: []string{"ad.intra.regen-bio.com"},
		BlockUDP:         true,
		BlockQUIC:        true,
	}
}
