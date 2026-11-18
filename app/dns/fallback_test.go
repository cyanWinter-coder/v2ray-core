package dns_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"google.golang.org/protobuf/types/known/anypb"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/app/dispatcher"
	. "github.com/v2fly/v2ray-core/v5/app/dns"
	"github.com/v2fly/v2ray-core/v5/app/policy"
	"github.com/v2fly/v2ray-core/v5/app/proxyman"
	_ "github.com/v2fly/v2ray-core/v5/app/proxyman/outbound"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	feature_dns "github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/proxy/freedom"
	"github.com/v2fly/v2ray-core/v5/testing/servers/udp"
)

type fallbackHandler struct {
	address string
}

func (h *fallbackHandler) ServeDNS(w mdns.ResponseWriter, request *mdns.Msg) {
	response := new(mdns.Msg)
	response.SetReply(request)
	for _, question := range request.Question {
		if question.Qtype == mdns.TypeA {
			record, _ := mdns.NewRR(question.Name + " IN A " + h.address)
			response.Answer = append(response.Answer, record)
		}
	}
	_ = w.WriteMsg(response)
}

func startFallbackServer(t *testing.T, address string) (*mdns.Server, net.Port) {
	t.Helper()
	port := udp.PickPort()
	server := &mdns.Server{
		Addr:    "127.0.0.1:" + port.String(),
		Net:     "udp",
		Handler: &fallbackHandler{address: address},
		UDPSize: 1200,
	}
	go func() {
		_ = server.ListenAndServe()
	}()
	time.Sleep(200 * time.Millisecond)
	t.Cleanup(func() {
		_ = server.Shutdown()
	})
	return server, port
}

func udpEndpoint(port net.Port) *net.Endpoint {
	return &net.Endpoint{
		Network: net.Network_UDP,
		Address: &net.IPOrDomain{
			Address: &net.IPOrDomain_Ip{
				Ip: []byte{127, 0, 0, 1},
			},
		},
		Port: uint32(port),
	}
}

func unreachableUDPPort(t *testing.T) net.Port {
	t.Helper()
	port := udp.PickPort()
	echo := &mdns.Server{
		Addr: "127.0.0.1:" + port.String(),
		Net:  "udp",
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, _ *mdns.Msg) {
			// Keep the listener alive without answering so the client times out.
		}),
	}
	go func() {
		_ = echo.ListenAndServe()
	}()
	time.Sleep(200 * time.Millisecond)
	t.Cleanup(func() {
		_ = echo.Shutdown()
	})
	return port
}

func newDNSInstance(t *testing.T, config *Config) (*DNS, feature_dns.Client) {
	t.Helper()
	coreConfig := &core.Config{
		App: []*anypb.Any{
			serial.ToTypedMessage(config),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&policy.Config{}),
		},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
		}},
	}
	instance, err := core.New(coreConfig)
	common.Must(err)
	client := instance.GetFeature(feature_dns.ClientType()).(feature_dns.Client)
	dnsServer, ok := client.(*DNS)
	if !ok {
		t.Fatalf("unexpected DNS client type %T", client)
	}
	return dnsServer, client
}

func TestDNSFallbackByDomainAfterPrimaryTimeout(t *testing.T) {
	_, fallbackPort := startFallbackServer(t, "203.0.113.9")
	primaryPort := unreachableUDPPort(t)

	config := &Config{
		NameServer: []*NameServer{{
			Address: udpEndpoint(primaryPort),
			Tag:     "primary",
			PrioritizedDomain: []*NameServer_PriorityDomain{{
				Type:   DomainMatchingType_Subdomain,
				Domain: "example.test",
			}},
			FallbackServer: []*FallbackServer{{
				Address: udpEndpoint(fallbackPort),
				Tag:     "fallback",
			}},
		}},
	}
	dnsServer, client := newDNSInstance(t, config)

	ips, err := client.LookupIP("host.example.test")
	if err != nil {
		t.Fatal("unexpected lookup error: ", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IP{203, 0, 113, 9}) {
		t.Fatalf("unexpected fallback IPs: %v", ips)
	}

	trace, found := dnsServer.LastLookup("host.example.test")
	if !found {
		t.Fatal("lookup trace not recorded")
	}
	if trace.SelectedServer == "" || trace.SelectedServer == "primary" {
		t.Fatalf("unexpected selected server: %q", trace.SelectedServer)
	}
	if len(trace.Attempts) != 2 {
		t.Fatalf("expected primary and fallback attempts, got %d", len(trace.Attempts))
	}
	if trace.Attempts[0].Fallback {
		t.Fatal("first attempt should be the primary server")
	}
	if !trace.Attempts[1].Fallback {
		t.Fatal("second attempt should be the fallback server")
	}
	if trace.Attempts[0].Duration <= 0 || trace.Attempts[1].Duration <= 0 {
		t.Fatalf("attempt durations were not recorded: %#v", trace.Attempts)
	}

	// Fallback servers are scoped to the domain suffix that selected the
	// primary server; they must not become global servers.
	if _, err := client.LookupIP("outside.test"); err == nil {
		t.Fatal("expected no matching name server for outside.test")
	}
}

func TestDNSFallbackAllServersFailWithoutStaleAnswer(t *testing.T) {
	primaryPort := unreachableUDPPort(t)
	fallbackPort := unreachableUDPPort(t)

	config := &Config{
		NameServer: []*NameServer{{
			Address: udpEndpoint(primaryPort),
			Tag:     "primary",
			PrioritizedDomain: []*NameServer_PriorityDomain{{
				Type:   DomainMatchingType_Subdomain,
				Domain: "example.test",
			}},
			FallbackServer: []*FallbackServer{{
				Address: udpEndpoint(fallbackPort),
				Tag:     "fallback",
			}},
		}},
	}
	dnsServer, client := newDNSInstance(t, config)

	ips, err := client.LookupIP("all-fail.example.test")
	if err == nil {
		t.Fatalf("expected lookup failure, got %v", ips)
	}
	var lookupErr *LookupError
	if !errors.As(err, &lookupErr) {
		t.Fatalf("expected LookupError, got %T: %v", err, err)
	}
	if len(lookupErr.Attempts) != 2 {
		t.Fatalf("expected two failed attempts, got %d", len(lookupErr.Attempts))
	}
	for _, text := range []string{"all-fail.example.test", "primary", "fallback"} {
		if !strings.Contains(err.Error(), text) {
			t.Fatalf("error should contain %q: %v", text, err)
		}
	}
	if len(ips) != 0 {
		t.Fatalf("expected no stale IPs, got %v", ips)
	}
	trace, found := dnsServer.LastLookup("all-fail.example.test")
	if !found || trace.Err == nil || len(trace.Attempts) != 2 {
		t.Fatalf("unexpected failure trace: %#v", trace)
	}
}
