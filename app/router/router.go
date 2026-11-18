package router

//go:generate go run github.com/v2fly/v2ray-core/v5/common/errors/errorgen

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/platform"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/outbound"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	routing_dns "github.com/v2fly/v2ray-core/v5/features/routing/dns"
	"github.com/v2fly/v2ray-core/v5/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v5/infra/conf/geodata"
)

var (
	// ErrRuleVersionConflict is returned when a hot update attempts to install
	// a rule set whose version is not newer than the active one.
	ErrRuleVersionConflict = errors.New("routing rule version conflict")
	// ErrInvalidRoutingConfig is returned when a hot update contains invalid
	// rules. The active rule set is left untouched.
	ErrInvalidRoutingConfig = errors.New("invalid routing rule configuration")
)

type routeSnapshot struct {
	version        uint64
	domainStrategy DomainStrategy
	rules          []*Rule
	balancers      map[string]*Balancer
}

// Router is an implementation of routing.Router.
type Router struct {
	dns        dns.Client
	ohm        outbound.Manager
	dispatcher routing.Dispatcher
	ctx        context.Context

	updateMu sync.Mutex
	snapshot atomic.Pointer[routeSnapshot]
}

// Route is an implementation of routing.Route.
type Route struct {
	routing.Context
	outboundGroupTags []string
	outboundTag       string
	sessionAttributes map[string]string
	ruleVersion       uint64
	ruleIdentifier    string
}

// Init initializes the Router.
func (r *Router) Init(ctx context.Context, config *Config, d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
	r.dns = d
	r.ohm = ohm
	r.dispatcher = dispatcher
	r.ctx = ctx
	if config == nil {
		return newError(ErrInvalidRoutingConfig, ": nil config")
	}

	snapshot, err := r.buildSnapshot(ctx, config, config.GetVersion())
	if err != nil {
		return err
	}
	r.snapshot.Store(snapshot)
	return nil
}

func (r *Router) buildSnapshot(ctx context.Context, config *Config, version uint64) (*routeSnapshot, error) {
	if config == nil {
		return nil, newError(ErrInvalidRoutingConfig, ": nil config")
	}
	balancers := make(map[string]*Balancer, len(config.BalancingRule))
	for _, rule := range config.BalancingRule {
		balancer, err := rule.Build(r.ohm, r.dispatcher)
		if err != nil {
			return nil, newError("failed to build balancer ", rule.GetTag()).Base(err)
		}
		balancer.InjectContext(ctx)
		balancers[rule.Tag] = balancer
	}

	rules := make([]*Rule, 0, len(config.Rule))
	for ruleIndex, rule := range config.Rule {
		if rule == nil {
			return nil, newError(ErrInvalidRoutingConfig, ": routing rule ", ruleIdentifier(rule, ruleIndex), " is nil")
		}
		cond, err := rule.BuildCondition()
		if err != nil {
			return nil, newError(ErrInvalidRoutingConfig, ": routing rule ", ruleIdentifier(rule, ruleIndex),
				" for domain ", ruleDomainSummary(rule)).Base(err)
		}
		rr := &Rule{
			ID:            ruleIdentifier(rule, ruleIndex),
			Condition:     cond,
			Tag:           rule.GetTag(),
			SetAttributes: rule.GetSetAttribute(),
		}
		btag := rule.GetBalancingTag()
		if len(btag) > 0 {
			brule, found := balancers[btag]
			if !found {
				return nil, newError(ErrInvalidRoutingConfig, ": routing rule ", ruleIdentifier(rule, ruleIndex),
					" references missing balancer ", btag, " for domain ", ruleDomainSummary(rule))
			}
			rr.Balancer = brule
		}
		rules = append(rules, rr)
	}

	return &routeSnapshot{
		version:        version,
		domainStrategy: config.DomainStrategy,
		rules:          rules,
		balancers:      balancers,
	}, nil
}

func ruleIdentifier(rule *RoutingRule, index int) string {
	if rule != nil && rule.GetRuleId() != "" {
		return rule.GetRuleId()
	}
	return fmt.Sprintf("rule[%d]", index)
}

func ruleDomainSummary(rule *RoutingRule) string {
	if rule == nil || len(rule.Domain) == 0 {
		return "<none>"
	}
	domains := rule.Domain
	if len(domains) > 3 {
		domains = domains[:3]
	}
	values := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain != nil {
			values = append(values, domain.Value)
		}
	}
	return fmt.Sprint(values)
}

// UpdateRules atomically replaces the active routing rules. Existing Route
// objects keep the outbound chosen from the snapshot they were created with.
//
// The optional expectedVersion is the version the caller expects to be active.
// A mismatch, a version that does not increase, or an invalid new rule set
// rejects the update and leaves the previous snapshot in use.
func (r *Router) UpdateRules(config *Config, expectedVersion ...uint64) error {
	if config == nil {
		return newError(ErrInvalidRoutingConfig, ": nil config")
	}

	r.updateMu.Lock()
	defer r.updateMu.Unlock()

	current := r.snapshot.Load()
	var currentVersion uint64
	if current != nil {
		currentVersion = current.version
	}
	if len(expectedVersion) > 0 && expectedVersion[0] != currentVersion {
		return newError(ErrRuleVersionConflict, ": expected active version ", expectedVersion[0],
			", actual version ", currentVersion)
	}

	version := config.GetVersion()
	switch {
	case version == 0:
		version = currentVersion + 1
	case version <= currentVersion:
		return newError(ErrRuleVersionConflict, ": new version ", version,
			" is not newer than active version ", currentVersion)
	}

	buildCtx := r.ctx
	if buildCtx == nil {
		buildCtx = context.Background()
	}
	snapshot, err := r.buildSnapshot(buildCtx, config, version)
	if err != nil {
		return err
	}
	r.snapshot.Store(snapshot)
	newError("routing rules updated to version ", version).AtInfo().WriteToLog()
	return nil
}

// Reload is an alias of UpdateRules.
func (r *Router) Reload(config *Config, expectedVersion ...uint64) error {
	return r.UpdateRules(config, expectedVersion...)
}

// ReloadRules is an alias of UpdateRules.
func (r *Router) ReloadRules(config *Config, expectedVersion ...uint64) error {
	return r.UpdateRules(config, expectedVersion...)
}

// UpdateConfig is an alias of UpdateRules.
func (r *Router) UpdateConfig(config *Config, expectedVersion ...uint64) error {
	return r.UpdateRules(config, expectedVersion...)
}

// ReloadConfig is an alias of UpdateRules.
func (r *Router) ReloadConfig(config *Config, expectedVersion ...uint64) error {
	return r.UpdateRules(config, expectedVersion...)
}

// UpdateRulesWithVersion installs a rule set with an explicit version.
func (r *Router) UpdateRulesWithVersion(version uint64, config *Config) error {
	if config == nil {
		return newError(ErrInvalidRoutingConfig, ": nil config")
	}
	configCopy := *config
	configCopy.Version = version
	return r.UpdateRules(&configCopy)
}

// UpdateRulesVersion is an alias of UpdateRulesWithVersion.
func (r *Router) UpdateRulesVersion(version uint64, config *Config) error {
	return r.UpdateRulesWithVersion(version, config)
}

// Version returns the active routing rule version.
func (r *Router) Version() uint64 {
	snapshot := r.snapshot.Load()
	if snapshot == nil {
		return 0
	}
	return snapshot.version
}

// RulesVersion is an alias of Version.
func (r *Router) RulesVersion() uint64 {
	return r.Version()
}

// PickRoute implements routing.Router.
func (r *Router) PickRoute(ctx routing.Context) (routing.Route, error) {
	snapshot, rule, ctx, err := r.pickRouteInternal(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := rule.GetTag()
	if err != nil {
		routeErr := newError("routing rule ", rule.Identifier(), " (version ", snapshot.version,
			") failed to choose outbound for domain ", ctx.GetTargetDomain(), ": ").Base(err)
		routeErr.AtWarning().WriteToLog()
		return nil, routeErr
	}
	route := &Route{
		Context:        ctx,
		outboundTag:    tag,
		ruleVersion:    snapshot.version,
		ruleIdentifier: rule.Identifier(),
	}
	if len(rule.SetAttributes) > 0 {
		route.sessionAttributes = make(map[string]string, len(rule.SetAttributes))
		for _, attr := range rule.SetAttributes {
			if attr == nil || attr.Key == "" {
				continue
			}
			route.sessionAttributes[attr.Key] = attr.Value
		}
		if len(route.sessionAttributes) == 0 {
			route.sessionAttributes = nil
		}
	}
	return route, nil
}

func (r *Router) pickRouteInternal(ctx routing.Context) (*routeSnapshot, *Rule, routing.Context, error) {
	// SkipDNSResolve is set from DNS module.
	// the DOH remote server maybe a domain name,
	// this prevents cycle resolving dead loop
	skipDNSResolve := ctx.GetSkipDNSResolve()
	snapshot := r.snapshot.Load()
	if snapshot == nil {
		return nil, nil, ctx, common.ErrNoClue
	}

	if snapshot.domainStrategy == DomainStrategy_IpOnDemand && !skipDNSResolve {
		ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)
	}

	for _, rule := range snapshot.rules {
		if rule.Apply(ctx) {
			return snapshot, rule, ctx, nil
		}
	}

	if snapshot.domainStrategy != DomainStrategy_IpIfNonMatch || len(ctx.GetTargetDomain()) == 0 || skipDNSResolve {
		return snapshot, nil, ctx, common.ErrNoClue
	}

	ctx = routing_dns.ContextWithDNSClient(ctx, r.dns)

	// Try applying rules again if we have IPs.
	for _, rule := range snapshot.rules {
		if rule.Apply(ctx) {
			return snapshot, rule, ctx, nil
		}
	}

	return snapshot, nil, ctx, common.ErrNoClue
}

// Start implements common.Runnable.
func (r *Router) Start() error {
	return nil
}

// Close implements common.Closable.
func (r *Router) Close() error {
	return nil
}

// Type implements common.HasType.
func (*Router) Type() interface{} {
	return routing.RouterType()
}

// GetOutboundGroupTags implements routing.Route.
func (r *Route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

// GetOutboundTag implements routing.Route.
func (r *Route) GetOutboundTag() string {
	return r.outboundTag
}

// GetRuleVersion returns the routing rule snapshot version used for this route.
func (r *Route) GetRuleVersion() uint64 {
	return r.ruleVersion
}

// GetRuleIdentifier returns the identifier of the rule that produced this route.
func (r *Route) GetRuleIdentifier() string {
	return r.ruleIdentifier
}

func (r *Route) GetSessionAttributes() map[string]string {
	if r == nil || len(r.sessionAttributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(r.sessionAttributes))
	for key, value := range r.sessionAttributes {
		out[key] = value
	}
	return out
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Router)
		if err := core.RequireFeatures(ctx, func(d dns.Client, ohm outbound.Manager, dispatcher routing.Dispatcher) error {
			return r.Init(ctx, config.(*Config), d, ohm, dispatcher)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))

	common.Must(common.RegisterConfig((*SimplifiedConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		ctx = cfgcommon.NewConfigureLoadingContext(ctx)

		geoloadername := platform.NewEnvFlag("v2ray.conf.geoloader").GetValue(func() string {
			return "standard"
		})

		if loader, err := geodata.GetGeoDataLoader(geoloadername); err == nil {
			cfgcommon.SetGeoDataLoader(ctx, loader)
		} else {
			return nil, newError("unable to create geo data loader ").Base(err)
		}

		cfgEnv := cfgcommon.GetConfigureLoadingEnvironment(ctx)
		geoLoader := cfgEnv.GetGeoLoader()

		simplifiedConfig := config.(*SimplifiedConfig)

		var routingRules []*RoutingRule

		for _, v := range simplifiedConfig.Rule {
			rule := new(RoutingRule)
			rule.RuleId = v.RuleId

			for _, geo := range v.Geoip {
				if geo.Code != "" {
					filepath := "geoip.dat"
					if geo.FilePath != "" {
						filepath = geo.FilePath
					} else {
						geo.CountryCode = geo.Code
					}
					var err error
					geo.Cidr, err = geoLoader.LoadIP(filepath, geo.Code)
					if err != nil {
						return nil, newError("unable to load geoip").Base(err)
					}
				}
			}
			rule.Geoip = v.Geoip

			for _, geo := range v.SourceGeoip {
				if geo.Code != "" {
					filepath := "geoip.dat"
					if geo.FilePath != "" {
						filepath = geo.FilePath
					} else {
						geo.CountryCode = geo.Code
					}
					var err error
					geo.Cidr, err = geoLoader.LoadIP(filepath, geo.Code)
					if err != nil {
						return nil, newError("unable to load geoip").Base(err)
					}
				}
			}
			rule.SourceGeoip = v.SourceGeoip

			for _, geo := range v.GeoDomain {
				if geo.Code != "" {
					filepath := "geosite.dat"
					if geo.FilePath != "" {
						filepath = geo.FilePath
					}
					var err error
					geo.Domain, err = geoLoader.LoadGeoSiteWithAttr(filepath, geo.Code)
					if err != nil {
						return nil, newError("unable to load geodomain").Base(err)
					}
				}
			}
			if v.PortList != "" {
				portList := &cfgcommon.PortList{}
				err := portList.UnmarshalText(v.PortList)
				if err != nil {
					return nil, err
				}
				rule.PortList = portList.Build()
			}
			if v.SourcePortList != "" {
				portList := &cfgcommon.PortList{}
				err := portList.UnmarshalText(v.SourcePortList)
				if err != nil {
					return nil, err
				}
				rule.SourcePortList = portList.Build()
			}
			rule.Domain = v.Domain
			rule.GeoDomain = v.GeoDomain
			rule.Networks = v.Networks.GetNetwork()
			rule.Protocol = v.Protocol
			rule.Attributes = v.Attributes
			rule.SetAttribute = append(rule.SetAttribute, v.SetAttribute...)
			rule.UserEmail = v.UserEmail
			rule.InboundTag = v.InboundTag
			rule.DomainMatcher = v.DomainMatcher
			switch s := v.TargetTag.(type) {
			case *SimplifiedRoutingRule_Tag:
				rule.TargetTag = &RoutingRule_Tag{s.Tag}
			case *SimplifiedRoutingRule_BalancingTag:
				rule.TargetTag = &RoutingRule_BalancingTag{s.BalancingTag}
			}
			routingRules = append(routingRules, rule)
		}

		fullConfig := &Config{
			DomainStrategy: simplifiedConfig.DomainStrategy,
			Rule:           routingRules,
			BalancingRule:  simplifiedConfig.BalancingRule,
			Version:        simplifiedConfig.Version,
		}
		return common.CreateObject(ctx, fullConfig)
	}))
}
