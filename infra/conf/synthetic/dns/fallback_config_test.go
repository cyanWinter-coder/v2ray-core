package dns_test

import (
	"encoding/json"
	"testing"

	"github.com/v2fly/v2ray-core/v5/common/net"
	dns2 "github.com/v2fly/v2ray-core/v5/infra/conf/synthetic/dns"
)

func TestNameServerFallbackServersConfig(t *testing.T) {
	raw := []byte(`{
		"address": "8.8.8.8",
		"port": 53,
		"fallbackServers": [
			"1.1.1.1:5353",
			{"address": "9.9.9.9", "port": 53, "tag": "secondary", "network": "udp"}
		]
	}`)
	config := new(dns2.NameServerConfig)
	if err := json.Unmarshal(raw, config); err != nil {
		t.Fatal("unexpected config error: ", err)
	}
	nameServer, err := config.Build()
	if err != nil {
		t.Fatal("unexpected build error: ", err)
	}
	if len(nameServer.FallbackServer) != 2 {
		t.Fatalf("expected 2 fallback servers, got %d", len(nameServer.FallbackServer))
	}
	if got := nameServer.FallbackServer[0].Address; got.Port != 5353 || got.Network != net.Network_UDP {
		t.Fatalf("unexpected first fallback endpoint: %v", got)
	}
	if got := nameServer.FallbackServer[1].Tag; got != "secondary" {
		t.Fatalf("unexpected fallback tag: %q", got)
	}
}
