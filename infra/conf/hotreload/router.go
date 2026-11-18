package hotreload

import (
	"context"
	"encoding/json"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/app/router"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/infra/conf/v5cfg"
)

// RouterRuleReloader is implemented by routers that support atomic rule hot
// updates. UpdateRules must either install the complete rule set or leave the
// previous version active.
type RouterRuleReloader interface {
	UpdateRules(config *router.Config, expectedVersion ...uint64) error
}

// ReloadRouterConfig parses a JSONv5 router configuration and applies it to a
// running instance. The configuration "version" field must be newer than the
// active routing rule version.
func ReloadRouterConfig(ctx context.Context, instance *core.Instance, rawConfig json.RawMessage) error {
	if instance == nil {
		return newError("nil core instance")
	}
	config, err := v5cfg.LoadHeterogeneousConfigFromRawJSON(ctx, "service", "router", rawConfig)
	if err != nil {
		return newError("failed to parse Router config").Base(err)
	}
	routerConfig, ok := config.(*router.Config)
	if !ok {
		return newError("router config has unexpected type")
	}
	feature := instance.GetFeature(routing.RouterType())
	reloader, ok := feature.(RouterRuleReloader)
	if !ok {
		return newError("router does not support rule hot updates")
	}
	return reloader.UpdateRules(routerConfig)
}
