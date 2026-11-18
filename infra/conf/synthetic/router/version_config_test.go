package router_test

import (
	"encoding/json"
	"testing"

	router2 "github.com/v2fly/v2ray-core/v5/infra/conf/synthetic/router"
)

func TestRouterVersionAndRuleIDConfig(t *testing.T) {
	raw := []byte(`{
		"version": 7,
		"rules": [
			{
				"type": "field",
				"id": "rule-7",
				"outboundTag": "direct",
				"domain": ["full:example.com"]
			}
		]
	}`)
	config := new(router2.RouterConfig)
	if err := json.Unmarshal(raw, config); err != nil {
		t.Fatal("unexpected config error: ", err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal("unexpected build error: ", err)
	}
	if built.Version != 7 {
		t.Fatalf("expected version 7, got %d", built.Version)
	}
	if len(built.Rule) != 1 || built.Rule[0].GetRuleId() != "rule-7" {
		t.Fatalf("unexpected rule ID: %#v", built.Rule)
	}
}
