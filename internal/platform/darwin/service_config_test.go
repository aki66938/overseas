package darwin

import (
	"corp.example/overseas-access-gateway/internal/accessmodel"
	"encoding/json"
	"testing"
)

func validServiceConfig() ServiceConfig {
	return ServiceConfig{SchemaVersion: 1, OwnerUID: 501, CoreSHA256: PinnedCoreSHA256, Policy: accessmodel.Policy{SchemaVersion: 2, Mode: "poc", BlockUDP: true, BlockQUIC: true, Nodes: []accessmodel.Node{{ID: "approved", Transport: "http-connect", Address: "172.20.9.15", Port: 8080}}, CorporateCIDRs: []string{"172.20.8.0/22"}, CorporateDNS: []string{"172.20.9.1"}}}
}
func TestServiceConfigRejectsUntrustedInputs(t *testing.T) {
	for _, change := range []func(*ServiceConfig){func(c *ServiceConfig) { c.SchemaVersion = 2 }, func(c *ServiceConfig) { c.OwnerUID = 0 }, func(c *ServiceConfig) {
		c.CoreSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}, func(c *ServiceConfig) { c.Policy.SchemaVersion = 1 }, func(c *ServiceConfig) { c.Policy.Nodes[0].Address = "192.0.2.1" }} {
		c := validServiceConfig()
		change(&c)
		data, _ := json.Marshal(c)
		if _, err := ParseServiceConfig(data); err == nil {
			t.Fatal("accepted unsafe config")
		}
	}
	c := validServiceConfig()
	data, _ := json.Marshal(c)
	if _, err := ParseServiceConfig(data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(data, []byte("{}")...), []byte(`{"executable":"/tmp/evil"}`), append([]byte(`{"unexpected":true,`), data[1:]...)} {
		if _, err := ParseServiceConfig(bad); err == nil {
			t.Fatal("accepted invalid JSON schema")
		}
	}
}
