package router_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"

	. "github.com/v2fly/v2ray-core/v5/app/router"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/session"
	routing_session "github.com/v2fly/v2ray-core/v5/features/routing/session"
	"github.com/v2fly/v2ray-core/v5/testing/mocks"
)

func newTestRouter(t *testing.T, config *Config) *Router {
	t.Helper()
	mockCtl := gomock.NewController(t)
	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	r := new(Router)
	common.Must(r.Init(context.Background(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))
	return r
}

func pickTestRoute(t *testing.T, r *Router, domain string) (string, uint64, string) {
	t.Helper()
	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{
		Target: net.TCPDestination(net.DomainAddress(domain), 80),
	})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	typed, ok := route.(interface {
		GetRuleVersion() uint64
		GetRuleIdentifier() string
	})
	if !ok {
		t.Fatal("route does not expose rule version")
	}
	return route.GetOutboundTag(), typed.GetRuleVersion(), typed.GetRuleIdentifier()
}

func hotUpdateConfig(version uint64, tag, ruleID string) *Config {
	return &Config{
		Version: version,
		Rule: []*RoutingRule{
			{
				RuleId: ruleID,
				TargetTag: &RoutingRule_Tag{
					Tag: tag,
				},
				Domain: []*routercommon.Domain{{
					Type:  routercommon.Domain_Full,
					Value: "example.com",
				}},
			},
		},
	}
}

func TestRouterHotUpdateUsesNewRulesForNewConnections(t *testing.T) {
	r := newTestRouter(t, hotUpdateConfig(1, "old-out", "old-rule"))

	oldTag, oldVersion, oldRule := pickTestRoute(t, r, "example.com")
	if oldTag != "old-out" || oldVersion != 1 || oldRule != "old-rule" {
		t.Fatalf("unexpected initial route: tag=%s version=%d rule=%s", oldTag, oldVersion, oldRule)
	}

	if err := r.UpdateRules(hotUpdateConfig(2, "new-out", "new-rule")); err != nil {
		t.Fatal("unexpected update error: ", err)
	}

	newTag, newVersion, newRule := pickTestRoute(t, r, "example.com")
	if newTag != "new-out" || newVersion != 2 || newRule != "new-rule" {
		t.Fatalf("unexpected updated route: tag=%s version=%d rule=%s", newTag, newVersion, newRule)
	}

	// The route selected before the update is an immutable decision and must
	// continue to use the old outbound for the lifetime of that connection.
	if oldTag != "old-out" || oldVersion != 1 || oldRule != "old-rule" {
		t.Fatalf("existing route changed after hot update: tag=%s version=%d rule=%s", oldTag, oldVersion, oldRule)
	}
}

func TestRouterHotUpdateRejectsInvalidRulesAndKeepsOldVersion(t *testing.T) {
	r := newTestRouter(t, hotUpdateConfig(1, "old-out", "old-rule"))

	invalid := hotUpdateConfig(2, "bad-out", "bad-rule")
	invalid.Rule[0].Domain = []*routercommon.Domain{{
		Type:  routercommon.Domain_Type(99),
		Value: "example.com",
	}}
	err := r.UpdateRules(invalid)
	if err == nil {
		t.Fatal("expected invalid rule update to fail")
	}
	if !errors.Is(err, ErrInvalidRoutingConfig) {
		t.Fatalf("expected ErrInvalidRoutingConfig, got %v", err)
	}
	if !strings.Contains(err.Error(), "bad-rule") || !strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error should contain rule ID and domain: %v", err)
	}
	if r.Version() != 1 {
		t.Fatalf("invalid update changed active version to %d", r.Version())
	}
	if tag, _, _ := pickTestRoute(t, r, "example.com"); tag != "old-out" {
		t.Fatalf("invalid update changed active route to %s", tag)
	}
}

func TestRouterHotUpdateRejectsMissingBalancer(t *testing.T) {
	r := newTestRouter(t, hotUpdateConfig(1, "old-out", "old-rule"))

	invalid := &Config{
		Version: 2,
		Rule: []*RoutingRule{{
			RuleId: "missing-balancer-rule",
			TargetTag: &RoutingRule_BalancingTag{
				BalancingTag: "does-not-exist",
			},
			Networks: []net.Network{net.Network_TCP},
		}},
	}
	err := r.UpdateRules(invalid)
	if err == nil {
		t.Fatal("expected missing balancer update to fail")
	}
	if !errors.Is(err, ErrInvalidRoutingConfig) {
		t.Fatalf("expected ErrInvalidRoutingConfig, got %v", err)
	}
	if r.Version() != 1 {
		t.Fatalf("missing reference changed active version to %d", r.Version())
	}
}

func TestRouterHotUpdateRejectsVersionConflict(t *testing.T) {
	r := newTestRouter(t, hotUpdateConfig(2, "old-out", "old-rule"))

	if err := r.UpdateRules(hotUpdateConfig(2, "new-out", "new-rule")); !errors.Is(err, ErrRuleVersionConflict) {
		t.Fatalf("expected version conflict, got %v", err)
	}
	if err := r.UpdateRules(hotUpdateConfig(3, "new-out", "new-rule"), 1); !errors.Is(err, ErrRuleVersionConflict) {
		t.Fatalf("expected expected-version conflict, got %v", err)
	}
	if err := r.UpdateRules(hotUpdateConfig(3, "new-out", "new-rule"), 2); err != nil {
		t.Fatal("unexpected update error: ", err)
	}
	if r.Version() != 3 {
		t.Fatalf("expected version 3, got %d", r.Version())
	}
}
