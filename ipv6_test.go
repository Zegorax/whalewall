package whalewall

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/matryer/is"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/whalewall/dnsproxy"
)

const (
	enabledTrue = "true"
	netDefault  = "default"
	dummyDNS    = "192.0.2.53"
	allowHTTPS  = `
output:
  - proto: tcp
    dst_ports:
      - 443`
)

var (
	gatewayAddr6 = netip.MustParseAddr("fd00:1::1")
	cont1Addr6   = netip.MustParseAddr("fd00:1::2")
	dstAddr6     = netip.MustParseAddr("2001:db8::1")
)

type fakeDNS struct {
	mtx        sync.Mutex
	listening  map[netip.AddrPort]int
	policies   map[netip.Addr]*dnsproxy.Policy
	acquireErr error
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{
		listening: make(map[netip.AddrPort]int),
		policies:  make(map[netip.Addr]*dnsproxy.Policy),
	}
}

func (f *fakeDNS) Acquire(a netip.AddrPort) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if f.acquireErr != nil {
		return f.acquireErr
	}
	f.listening[a]++
	return nil
}

func (f *fakeDNS) Release(a netip.AddrPort) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	f.listening[a]--
	if f.listening[a] <= 0 {
		delete(f.listening, a)
	}
}

func (f *fakeDNS) Register(addrs []netip.Addr, p *dnsproxy.Policy) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, a := range addrs {
		f.policies[a] = p
	}
}

func (f *fakeDNS) Unregister(addrs []netip.Addr, p *dnsproxy.Policy) {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	for _, a := range addrs {
		if f.policies[a] == p {
			delete(f.policies, a)
		}
	}
}

func (f *fakeDNS) Close() {}

func (f *fakeDNS) policy(a netip.Addr) *dnsproxy.Policy {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	return f.policies[a]
}

type ipv6TestEnv struct {
	is  *is.I
	r   *RuleManager
	mfc *mockFirewall
	dns *fakeDNS
}

// newIPv6TestEnv creates a rule manager with a mock firewall that has
// Docker's chains for the given families.
func newIPv6TestEnv(t *testing.T, v6, dnsEnabled bool) *ipv6TestEnv {
	t.Helper()

	is := is.New(t)
	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))

	var opts []Option
	if dnsEnabled {
		opts = append(opts, WithDNS(DNSOptions{Port: 5353}))
	}
	r, err := NewRuleManager(context.Background(), logger, filepath.Join(t.TempDir(), "db.sqlite"), defaultTimeout, opts...)
	is.NoErr(err)
	t.Cleanup(func() { r.db.Close() })

	dockerCli := newMockDockerClient(nil)
	r.newDockerClient = func() (dockerClient, error) { return dockerCli, nil }

	firewallCreator := newMockFirewallCreator(logger)
	mfc := firewallCreator.newMockFirewall()
	for _, fam := range families {
		if fam.v6 && !v6 {
			continue
		}
		mfc.AddTable(fam.table)
		mfc.AddChain(&nftables.Chain{
			Name:  dockerChainName,
			Table: fam.table,
			Type:  nftables.ChainTypeFilter,
		})
	}
	is.NoErr(mfc.Flush())
	r.newFirewallClient = func() (firewallClient, error) {
		return firewallCreator.newMockFirewall(), nil
	}

	is.NoErr(r.init(context.Background()))
	is.NoErr(r.createBaseRules())
	if v6 {
		is.NoErr(r.ensureIPv6BaseRules())
	}

	env := &ipv6TestEnv{is: is, r: r, mfc: mfc}
	if dnsEnabled {
		env.dns = newFakeDNS()
		r.dns = env.dns
		r.dnsPolicies = make(map[string]*domainPolicy)
	}

	return env
}

// refresh updates the mock firewall's view of the firewall.
func (e *ipv6TestEnv) refresh() {
	e.is.NoErr(e.mfc.Flush())
}

func dualStackContainer(id, name string, labels map[string]string, dnsServers []string) types.ContainerJSON {
	labels[enabledLabel] = enabledTrue
	return types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:         id,
			Name:       "/" + name,
			HostConfig: &container.HostConfig{DNS: dnsServers},
		},
		Config: &container.Config{Labels: labels},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				netDefault: {
					Gateway:           gatewayAddr.String(),
					IPAddress:         cont1Addr.String(),
					IPv6Gateway:       gatewayAddr6.String(),
					GlobalIPv6Address: cont1Addr6.String(),
				},
			},
		},
	}
}

func chainOf(fam *family, name, id string) *nftables.Chain {
	return &nftables.Chain{Name: buildChainName(name, id), Table: fam.table}
}

func icmpv6Exprs(low, high byte) []expr.Any {
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Len:           1,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        0,
			DestRegister:  1,
		},
	}
	if low == high {
		exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{low}})
	} else {
		exprs = append(exprs,
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: []byte{low}},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: []byte{high}},
		)
	}
	return append(exprs, &expr.Counter{}, acceptVerdict)
}

func TestIPv6RuleCreation(t *testing.T) {
	t.Parallel()

	env := newIPv6TestEnv(t, true, false)
	is := env.is
	logger := zaptest.NewLogger(t)
	comparer := func(r1, r2 *nftables.Rule) bool { return rulesEqual(logger, r1, r2) }

	c := dualStackContainer(cont1ID, cont1Name, map[string]string{
		rulesLabel: `
output:
  - ips:
      - 2001:db8::1
      - 1.1.1.1
    proto: tcp
    dst_ports:
      - 443
  - ips:
      - 2001:db8:1::/48
    proto: udp
    dst_ports:
      - 53
  - proto: tcp
    dst_ports:
      - 8080`,
	}, nil)
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))

	env.refresh()
	// IPv6 container address is in the IPv6 jump map
	is.Equal(len(env.mfc.tables["ip6:"+filterTableName].Sets[containerAddrSetName]), 1)
	is.Equal(len(env.mfc.tables[filterTableName].Sets[containerAddrSetName]), 1)

	v4Chain := chainOf(family4, cont1Name, cont1ID)
	v6Chain := chainOf(family6, cont1Name, cont1ID)

	v4Rules, err := env.mfc.GetRules(family4.table, v4Chain)
	is.NoErr(err)
	v6Rules, err := env.mfc.GetRules(family6.table, v6Chain)
	is.NoErr(err)

	addr6 := cont1Addr6.AsSlice()
	lowNet, highNet := netip.MustParseAddr("2001:db8:1::"), netip.MustParseAddr("2001:db8:1:ffff:ffff:ffff:ffff:ffff")
	_ = lowNet
	_ = highNet

	expectedV6 := []*nftables.Rule{
		{Exprs: icmpv6Exprs(133, 133), UserData: []byte(cont1ID)},
		{Exprs: icmpv6Exprs(135, 136), UserData: []byte(cont1ID)},
		{Exprs: icmpv6Exprs(2, 2), UserData: []byte(cont1ID)},
		// 2001:db8::1 tcp/443, the IPv4 address of the same rule is not
		// part of the IPv6 chain
		{
			Exprs: slicesJoin(
				matchAddrExprs(addr6, family6.srcOffset),
				matchAddrExprs(dstAddr6.AsSlice(), family6.dstOffset),
				matchProtoExprs(unix.IPPROTO_TCP),
				matchPortExprs(443, dstPortOffset),
				matchConnStateExprs(stateNewEst),
				[]expr.Any{&expr.Counter{}, acceptVerdict},
			),
			UserData: []byte(cont1ID),
		},
		{
			Exprs: slicesJoin(
				matchAddrExprs(dstAddr6.AsSlice(), family6.srcOffset),
				matchAddrExprs(addr6, family6.dstOffset),
				matchProtoExprs(unix.IPPROTO_TCP),
				matchPortExprs(443, srcPortOffset),
				matchConnStateExprs(stateEst),
				[]expr.Any{&expr.Counter{}, acceptVerdict},
			),
			UserData: []byte(cont1ID),
		},
	}
	// the IPv6 chain has: ICMPv6 rules, 4 generated rules (2 each for the
	// first two output rules), 2 rules for the third rule, then the drop
	// rule. Only check the parts that matter for IPv6.
	is.True(len(v6Rules) >= 9)
	for i, want := range expectedV6 {
		if !hasRule(comparer, v6Rules, want) {
			t.Errorf("expected IPv6 rule %d is missing", i)
		}
	}

	// the drop rule is last in both chains
	is.True(cmpRule(comparer, createDropRule(v6Chain, cont1ID), v6Rules[len(v6Rules)-1]))
	is.True(cmpRule(comparer, createDropRule(v4Chain, cont1ID), v4Rules[len(v4Rules)-1]))

	// the 2001:db8:1::/48 range is only matched in the IPv6 chain, as a
	// 16 byte comparison
	foundRange := false
	for _, rule := range v6Rules {
		for _, e := range rule.Exprs {
			if cmp, ok := e.(*expr.Cmp); ok && len(cmp.Data) == 16 && cmp.Op == expr.CmpOpGte {
				foundRange = true
			}
		}
	}
	is.True(foundRange)
	for _, rule := range v4Rules {
		for _, e := range rule.Exprs {
			if cmp, ok := e.(*expr.Cmp); ok {
				is.True(len(cmp.Data) != 16) // no IPv6 data in the IPv4 chain
			}
			if p, ok := e.(*expr.Payload); ok && p.Base == expr.PayloadBaseNetworkHeader {
				is.Equal(p.Len, uint32(4))
			}
		}
	}

	// IPv6 rules use 16 byte address loads at the IPv6 header offsets
	for _, rule := range v6Rules {
		for _, e := range rule.Exprs {
			if p, ok := e.(*expr.Payload); ok && p.Base == expr.PayloadBaseNetworkHeader {
				is.Equal(p.Len, uint32(16))
				is.True(p.Offset == family6.srcOffset || p.Offset == family6.dstOffset)
			}
		}
	}

	// recreating the rules does not add any
	is.NoErr(env.r.createContainerRules(context.Background(), c, false))
	env.refresh()
	again, err := env.mfc.GetRules(family6.table, v6Chain)
	is.NoErr(err)
	is.Equal(len(again), len(v6Rules))
	againV4, err := env.mfc.GetRules(family4.table, v4Chain)
	is.NoErr(err)
	is.Equal(len(againV4), len(v4Rules))

	// deleting removes both chains and both set elements
	is.NoErr(env.r.deleteContainerRules(context.Background(), cont1ID, cont1Name))
	_, err = env.mfc.GetRules(family4.table, v4Chain)
	is.True(errors.Is(err, syscall.ENOENT))
	_, err = env.mfc.GetRules(family6.table, v6Chain)
	is.True(errors.Is(err, syscall.ENOENT))
	is.NoErr(env.mfc.Flush())
	is.Equal(len(env.mfc.tables["ip6:"+filterTableName].Sets[containerAddrSetName]), 0)
	is.Equal(len(env.mfc.tables[filterTableName].Sets[containerAddrSetName]), 0)

	// clearing removes the IPv6 base rules too
	is.NoErr(env.r.clearRules(context.Background()))
	is.NoErr(env.mfc.Flush())
	for key, ch := range env.mfc.chains {
		is.True(ch.Chain.Name != whalewallChainName) // chain left behind: key
		_ = key
	}
}

func hasRule(comparer func(r1, r2 *nftables.Rule) bool, rules []*nftables.Rule, want *nftables.Rule) bool {
	for _, rule := range rules {
		if cmpRule(comparer, want, rule) {
			return true
		}
	}
	return false
}

func cmpRule(comparer func(r1, r2 *nftables.Rule) bool, expected, got *nftables.Rule) bool {
	if expected.Table == nil {
		expected.Table = got.Table
	}
	return comparer(expected, got) && string(expected.UserData) == string(got.UserData)
}

func TestIPv6OnlyContainer(t *testing.T) {
	t.Parallel()

	env := newIPv6TestEnv(t, true, false)
	is := env.is

	c := dualStackContainer(cont1ID, cont1Name, map[string]string{
		rulesLabel: allowHTTPS,
	}, nil)
	ep := c.NetworkSettings.Networks["default"]
	ep.IPAddress = ""
	ep.Gateway = ""
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))

	env.refresh()
	// no IPv4 chain is created for a container without an IPv4 address
	_, err := env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.True(errors.Is(err, syscall.ENOENT))
	rules, err := env.mfc.GetRules(family6.table, chainOf(family6, cont1Name, cont1ID))
	is.NoErr(err)
	is.True(len(rules) > 0)
	is.Equal(len(env.mfc.tables[filterTableName].Sets[containerAddrSetName]), 0)
	is.Equal(len(env.mfc.tables["ip6:"+filterTableName].Sets[containerAddrSetName]), 1)

	is.NoErr(env.r.deleteContainerRules(context.Background(), cont1ID, cont1Name))
}

func TestIPv6NotManaged(t *testing.T) {
	t.Parallel()

	// Docker's IPv6 chains don't exist
	env := newIPv6TestEnv(t, false, false)
	is := env.is

	is.True(env.r.ensureIPv6BaseRules() != nil)

	c := dualStackContainer(cont1ID, cont1Name, map[string]string{}, nil)
	err := env.r.createContainerRules(context.Background(), c, true)
	is.True(err != nil)
	is.True(strings.Contains(err.Error(), "IPv6"))

	// nothing was created, not even for IPv4
	_, err = env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.True(errors.Is(err, syscall.ENOENT))

	// containers without IPv6 addresses are unaffected
	c4 := dualStackContainer(cont2ID, cont2Name, map[string]string{}, nil)
	ep := c4.NetworkSettings.Networks["default"]
	ep.GlobalIPv6Address = ""
	ep.IPv6Gateway = ""
	ep.IPAddress = cont2Addr.String()
	is.NoErr(env.r.createContainerRules(context.Background(), c4, true))
}

func TestDomainRuleCreation(t *testing.T) {
	t.Parallel()

	env := newIPv6TestEnv(t, true, true)
	is := env.is
	logger := zaptest.NewLogger(t)
	comparer := func(r1, r2 *nftables.Rule) bool { return rulesEqual(logger, r1, r2) }

	c := dualStackContainer(cont1ID, cont1Name, map[string]string{
		rulesLabel: `
output:
  - domains:
      - api.example.com
      - "*.example.net"
      - "**.cdn.example.org"
    proto: tcp
    dst_ports:
      - 443
  - proto: tcp
    ips:
      - 1.1.1.1
    dst_ports:
      - 80`,
	}, []string{dummyDNS})
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))

	env.refresh()
	setName4 := domainSetName(cont1ID, 0, family4)
	setName6 := domainSetName(cont1ID, 0, family6)
	is.Equal(setName4, "ww-container_on-0-4")
	_, ok := env.mfc.tables[filterTableName].Sets[setName4]
	is.True(ok)
	_, ok = env.mfc.tables["ip6:"+filterTableName].Sets[setName6]
	is.True(ok)
	// no set for the second rule
	_, ok = env.mfc.tables[filterTableName].Sets[domainSetName(cont1ID, 1, family4)]
	is.True(!ok)

	v4Chain := chainOf(family4, cont1Name, cont1ID)
	v4Rules, err := env.mfc.GetRules(family4.table, v4Chain)
	is.NoErr(err)

	addr4 := cont1Addr.AsSlice()
	lookup := func(offset uint32, name string, size uint32) []expr.Any {
		return []expr.Any{
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           size,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        offset,
				DestRegister:  1,
			},
			&expr.Lookup{SourceRegister: 1, SetName: name},
		}
	}
	// new connections have to match the set
	newRule := &nftables.Rule{
		Exprs: slicesJoin(
			matchAddrExprs(addr4, srcAddrOffset),
			lookup(dstAddrOffset, setName4, 4),
			matchProtoExprs(unix.IPPROTO_TCP),
			matchPortExprs(443, dstPortOffset),
			matchConnStateExprs(stateNew),
			[]expr.Any{&expr.Counter{}, acceptVerdict},
		),
		UserData: []byte(cont1ID),
	}
	// established connections do not, so they survive set elements expiring
	estOut := &nftables.Rule{
		Exprs: slicesJoin(
			matchAddrExprs(addr4, srcAddrOffset),
			matchProtoExprs(unix.IPPROTO_TCP),
			matchPortExprs(443, dstPortOffset),
			matchConnStateExprs(stateEst),
			[]expr.Any{&expr.Counter{}, acceptVerdict},
		),
		UserData: []byte(cont1ID),
	}
	estIn := &nftables.Rule{
		Exprs: slicesJoin(
			matchAddrExprs(addr4, dstAddrOffset),
			matchProtoExprs(unix.IPPROTO_TCP),
			matchPortExprs(443, srcPortOffset),
			matchConnStateExprs(stateEst),
			[]expr.Any{&expr.Counter{}, acceptVerdict},
		),
		UserData: []byte(cont1ID),
	}
	var found [3]bool
	for _, rule := range v4Rules {
		for i, want := range []*nftables.Rule{newRule, estOut, estIn} {
			if cmpRule(comparer, want, rule) {
				found[i] = true
			}
		}
	}
	is.Equal(found, [3]bool{true, true, true})

	// the container is allowed to reach the resolver on the gateway
	dnsAccess := func(proto int) *nftables.Rule {
		return &nftables.Rule{
			Exprs: slicesJoin(
				matchAddrExprs(addr4, srcAddrOffset),
				matchAddrExprs(gatewayAddr.AsSlice(), dstAddrOffset),
				matchProtoExprs(proto),
				matchPortExprs(5353, dstPortOffset),
				matchConnStateExprs(stateNewEst),
				[]expr.Any{&expr.Counter{}, acceptVerdict},
			),
			UserData: []byte(cont1ID),
		}
	}
	foundDNS := [2]bool{}
	for _, rule := range v4Rules {
		if cmpRule(comparer, dnsAccess(unix.IPPROTO_UDP), rule) {
			foundDNS[0] = true
		}
		if cmpRule(comparer, dnsAccess(unix.IPPROTO_TCP), rule) {
			foundDNS[1] = true
		}
	}
	is.Equal(foundDNS, [2]bool{true, true})

	// DNS queries are redirected to the resolver for both families
	for _, fam := range families {
		chain := natFamilyChain(fam)
		rules, err := env.mfc.GetRules(chain.Table, chain)
		is.NoErr(err)
		is.Equal(len(rules), 2) // udp and tcp
		var hasNAT bool
		for _, e := range rules[0].Exprs {
			if n, ok := e.(*expr.NAT); ok {
				hasNAT = n.Type == expr.NATTypeDestNAT
			}
		}
		is.True(hasNAT)
	}

	// the resolver listens on both gateways and knows the container
	is.Equal(len(env.dns.listening), 2)
	is.Equal(env.dns.listening[netip.AddrPortFrom(gatewayAddr, 5353)], 1)
	is.Equal(env.dns.listening[netip.AddrPortFrom(gatewayAddr6, 5353)], 1)
	p4 := env.dns.policy(cont1Addr)
	is.True(p4 != nil)
	is.True(env.dns.policy(cont1Addr6) == p4)
	is.True(p4.HasIPv6)
	is.True(p4.Match("api.example.com"))
	is.True(p4.Match("x.example.net"))
	is.True(!p4.Match("x.y.example.net"))
	is.True(p4.Match("x.y.cdn.example.org"))
	is.True(!p4.Match("cdn.example.org"))

	// allowing addresses adds them to the set of the right family
	defer env.refresh()
	err = p4.Allow(context.Background(), "api.example.com", []dnsproxy.Resolved{
		{Addr: netip.MustParseAddr("203.0.113.5"), TTL: 40 * time.Second},
		{Addr: netip.MustParseAddr("2001:db8::5"), TTL: 50 * time.Second},
	})
	is.NoErr(err)
	env.refresh()
	elems4 := env.mfc.tables[filterTableName].Sets[setName4]
	is.Equal(len(elems4), 1)
	is.Equal(elems4[0].Key, netip.MustParseAddr("203.0.113.5").AsSlice())
	is.Equal(elems4[0].Timeout, 40*time.Second)
	elems6 := env.mfc.tables["ip6:"+filterTableName].Sets[setName6]
	is.Equal(len(elems6), 1)
	is.Equal(elems6[0].Key, netip.MustParseAddr("2001:db8::5").AsSlice())
	is.Equal(elems6[0].Timeout, 50*time.Second)

	// a name that matches no rule opens nothing
	err = p4.Allow(context.Background(), "other.example.com", []dnsproxy.Resolved{
		{Addr: netip.MustParseAddr("203.0.113.6"), TTL: time.Minute},
	})
	is.NoErr(err)
	env.refresh()
	is.Equal(len(env.mfc.tables[filterTableName].Sets[setName4]), 1)

	// recreating the rules does not duplicate rules, NAT rules or listeners
	is.NoErr(env.r.createContainerRules(context.Background(), c, false))
	again, err := env.mfc.GetRules(family4.table, v4Chain)
	is.NoErr(err)
	is.Equal(len(again), len(v4Rules))
	natChain := natFamilyChain(family4)
	natRules, err := env.mfc.GetRules(natChain.Table, natChain)
	is.NoErr(err)
	is.Equal(len(natRules), 2)
	is.Equal(env.dns.listening[netip.AddrPortFrom(gatewayAddr, 5353)], 1)
	env.refresh()
	// existing set elements are kept
	is.Equal(len(env.mfc.tables[filterTableName].Sets[setName4]), 1)

	// deleting removes the sets, NAT rules, listeners and policy
	is.NoErr(env.r.deleteContainerRules(context.Background(), cont1ID, cont1Name))
	is.NoErr(env.mfc.Flush())
	_, ok = env.mfc.tables[filterTableName].Sets[setName4]
	is.True(!ok)
	_, ok = env.mfc.tables["ip6:"+filterTableName].Sets[setName6]
	is.True(!ok)
	natRules, err = env.mfc.GetRules(natChain.Table, natChain)
	is.NoErr(err)
	is.Equal(len(natRules), 0)
	is.Equal(len(env.dns.listening), 0)
	is.True(env.dns.policy(cont1Addr) == nil)
	is.True(env.dns.policy(cont1Addr6) == nil)
}

func TestDomainRulesFailClosed(t *testing.T) {
	t.Parallel()

	domainRules := `
output:
  - domains:
      - api.example.com
    proto: tcp
    dst_ports:
      - 443`

	tests := []struct {
		name       string
		dnsEnabled bool
		dnsServers []string
		rules      string
	}{
		{name: "dns flag disabled", dnsEnabled: false, dnsServers: []string{dummyDNS}, rules: domainRules},
		{name: "no dns option", dnsEnabled: true, rules: domainRules},
		{name: "invalid wildcard", dnsEnabled: true, dnsServers: []string{dummyDNS}, rules: `
output:
  - domains:
      - a.*.example.com
    proto: tcp
    dst_ports:
      - 443`},
		{name: "domains and ips", dnsEnabled: true, dnsServers: []string{dummyDNS}, rules: `
output:
  - domains:
      - api.example.com
    ips:
      - 1.1.1.1
    proto: tcp
    dst_ports:
      - 443`},
		{name: "unknown key", dnsEnabled: true, dnsServers: []string{dummyDNS}, rules: `
output:
  - domain: api.example.com`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newIPv6TestEnv(t, false, tt.dnsEnabled)
			is := env.is
			logger := zaptest.NewLogger(t)
			comparer := func(r1, r2 *nftables.Rule) bool { return rulesEqual(logger, r1, r2) }

			c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: tt.rules}, tt.dnsServers)
			ep := c.NetworkSettings.Networks["default"]
			ep.GlobalIPv6Address = ""
			ep.IPv6Gateway = ""
			is.NoErr(env.r.createContainerRules(context.Background(), c, true))

			// the container only has the rule that drops everything
			chain := chainOf(family4, cont1Name, cont1ID)
			rules, err := env.mfc.GetRules(family4.table, chain)
			is.NoErr(err)
			is.Equal(len(rules), 1)
			is.True(cmpRule(comparer, createDropRule(chain, cont1ID), rules[0]))
			env.refresh()
			is.Equal(len(env.mfc.tables[filterTableName].Sets), 1) // only the container address map

			// and is deleted like any other container
			is.NoErr(env.r.deleteContainerRules(context.Background(), cont1ID, cont1Name))
		})
	}
}

func TestDomainSetsAreNotCreatedForOtherRules(t *testing.T) {
	t.Parallel()

	env := newIPv6TestEnv(t, false, true)
	is := env.is

	c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: allowHTTPS}, nil)
	ep := c.NetworkSettings.Networks["default"]
	ep.GlobalIPv6Address = ""
	ep.IPv6Gateway = ""
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))

	env.refresh()
	is.Equal(len(env.mfc.tables[filterTableName].Sets), 1)
	is.Equal(len(env.dns.listening), 0)
	// no NAT table was created
	_, ok := env.mfc.tables[natTableName]
	is.True(!ok)
}

func TestDomainRuleResolverFailure(t *testing.T) {
	t.Parallel()

	env := newIPv6TestEnv(t, false, true)
	is := env.is
	env.dns.acquireErr = errors.New("address not available")

	c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: `
output:
  - domains:
      - api.example.com
    proto: tcp
    dst_ports:
      - 443`}, []string{dummyDNS})
	ep := c.NetworkSettings.Networks["default"]
	ep.GlobalIPv6Address = ""
	ep.IPv6Gateway = ""

	err := env.r.createContainerRules(context.Background(), c, true)
	is.True(err != nil)
	is.True(strings.Contains(err.Error(), "resolver"))
	is.True(env.dns.policy(cont1Addr) == nil)
}
