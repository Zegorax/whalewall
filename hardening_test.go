package whalewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/docker/docker/api/types/network"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/matryer/is"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/whalewall/dnsproxy"
)

// TestIPRulesKeepTheirFamily feeds unusual address, prefix and range
// spellings to the rule generator. Whatever is accepted must compare the
// same number of bytes as the packet field it was loaded from, otherwise
// a rule can match a wider set of addresses than written (a 4 byte
// compare of a 16 byte field matches a whole /32).
func TestIPRulesKeepTheirFamily(t *testing.T) {
	t.Parallel()

	ips := []string{
		"1.2.3.4",
		"1.2.3.0/24",
		"1.2.3.4-1.2.3.9",
		"::ffff:1.2.3.4",
		"::ffff:10.0.0.0/104",
		"::ffff:0.0.0.0/96",
		"::ffff:1.2.3.4-::ffff:1.2.3.9",
		"::/0",
		"::",
		"::1",
		"::-::ffff:ffff:ffff",
		"::ffff:0:0/80",
		"::ffff:0:0/90",
		"::ffff:0:0/95",
		"::fffe:ffff:ffff-::ffff:0:1",
		"0.0.0.0/0",
		"0.0.0.0",
		"255.255.255.255",
		"2001:db8::1",
		"2001:db8::/32",
		"2001:db8::1-2001:db8::9",
		"64:ff9b::1.2.3.4",
		"64:ff9b::/96",
	}
	for _, ip := range ips {
		for _, multi := range []bool{false, true} {
			name := ip
			list := ip
			if multi {
				name += " with another"
				list += ", 9.9.9.9, 2001:db8:ffff::1"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				is := is.New(t)

				env := newIPv6TestEnv(t, true, false)
				rules := fmt.Sprintf("output:\n  - ips: [%s]\n    proto: tcp\n    dst_ports: [80]\n", list)
				c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: rules}, nil)
				err := env.r.createContainerRules(context.Background(), c, true)
				if err != nil {
					// refusing is always safe
					t.Logf("REFUSED: %v", err)
					return
				}

				for _, fam := range families {
					chain := chainOf(fam, cont1Name, cont1ID)
					got, err := env.mfc.GetRules(fam.table, chain)
					is.NoErr(err)
					for i, rule := range got {
						size := 0
						for _, e := range rule.Exprs {
							switch e := e.(type) {
							case *expr.Payload:
								size = int(e.Len)
								t.Logf("%s rule %d loads %d bytes at %d", fam, i, e.Len, e.Offset)
							case *expr.Cmp:
								if size > 4 && len(e.Data) != size && e.Register == 1 && len(e.Data) > 1 {
									t.Errorf("%s rule %d compares %d bytes of a %d byte field: %v", fam, i, len(e.Data), size, e.Data)
								}
								if size == 4 && len(e.Data) > 4 {
									t.Errorf("%s rule %d compares %d bytes of a 4 byte field: %v", fam, i, len(e.Data), e.Data)
								}
							}
						}
					}
				}
			})
		}
	}
}

// TestSingleFamilyRulesDoNotOpenTheOtherFamily checks that a rule that
// only names addresses of one family doesn't turn into an unrestricted
// rule in the other family's table.
func TestSingleFamilyRulesDoNotOpenTheOtherFamily(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ips    string
		closed *family
	}{
		{name: "only v4", ips: "[1.2.3.4]", closed: family6},
		{name: "only v4 range", ips: "[1.2.3.4-1.2.3.9]", closed: family6},
		{name: "only v4 cidr", ips: "[10.0.0.0/8]", closed: family6},
		{name: "only mapped v4", ips: "[::ffff:1.2.3.4]", closed: family6},
		{name: "only v6", ips: "[2001:db8::1]", closed: family4},
		{name: "only v6 cidr", ips: "[2001:db8::/32]", closed: family4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := is.New(t)

			env := newIPv6TestEnv(t, true, false)
			rules := fmt.Sprintf("output:\n  - ips: %s\n    proto: tcp\n    dst_ports: [80]\n", tt.ips)
			c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: rules}, nil)
			if err := env.r.createContainerRules(context.Background(), c, true); err != nil {
				return // refusing is safe
			}

			got, err := env.mfc.GetRules(tt.closed.table, chainOf(tt.closed, cont1Name, cont1ID))
			is.NoErr(err)
			for i, rule := range got {
				if !hasAcceptOrQueueVerdict(rule) || isICMPv6(rule) {
					continue
				}
				if matchesTCP(rule) {
					t.Errorf("%s rule %d accepts tcp although the rule named only the other family", tt.closed, i)
				}
			}
		})
	}
}

func matchesTCP(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpEq && bytes.Equal(c.Data, []byte{unix.IPPROTO_TCP}) {
			return true
		}
	}
	return false
}

// TestHostileRulesAreContained gives whalewall rule labels meant to use
// up its time and memory. Each must end with the container isolated and
// must not take noticeable time.
func TestHostileRulesAreContained(t *testing.T) {
	t.Parallel()

	var aliases strings.Builder
	aliases.WriteString("a: &a [x,x,x,x,x,x,x,x,x]\n")
	for i, prev := 'b', 'a'; i <= 'k'; i, prev = i+1, i {
		fmt.Fprintf(&aliases, "%c: &%c [*%c,*%c,*%c,*%c,*%c,*%c,*%c,*%c,*%c]\n", i, i, prev, prev, prev, prev, prev, prev, prev, prev, prev)
	}
	aliases.WriteString("output:\n  - ips: *k\n    proto: tcp\n    dst_ports: [80]\n")

	manyDomains := make([]string, maxEntries+1)
	for i := range manyDomains {
		manyDomains[i] = fmt.Sprintf("h%d.example.com", i)
	}
	manyRules := strings.Repeat("  - proto: tcp\n    dst_ports: [80]\n", maxRules+1)

	tests := map[string]string{
		"alias bomb":    aliases.String(),
		"huge label":    "output:\n  - proto: tcp\n    dst_ports: [80]\n# " + strings.Repeat("x", maxRulesLabelSize),
		"many domains":  "output:\n  - domains: [" + strings.Join(manyDomains, ",") + "]\n    proto: tcp\n    dst_ports: [443]\n",
		"many rules":    "output:\n" + manyRules,
		"deep nesting":  "output:\n  - ips: " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n    proto: tcp\n    dst_ports: [80]\n",
		"long scalar":   "output:\n  - proto: tcp\n    dst_ports: [" + strings.Repeat("1", 1<<16) + "]\n",
		"many ports":    "output:\n  - proto: tcp\n    dst_ports: [" + strings.TrimSuffix(strings.Repeat("80,", maxEntries+1), ",") + "]\n",
		"binary":        "output:\n  - proto: tcp\x00\n",
		"unknown field": "output:\n  - proto: tcp\n    dst_ports: [80]\n    allow_all: true\n",
		"tag tricks":    "output:\n  - !!binary proto: tcp\n",
	}
	for name, rules := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			is := is.New(t)

			env := newIPv6TestEnv(t, true, false)
			c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: rules}, nil)

			start := time.Now()
			is.NoErr(env.r.createContainerRules(context.Background(), c, true))
			is.True(time.Since(start) < 5*time.Second)

			// whatever was in the label, nothing may be accepted
			for _, fam := range families {
				got, err := env.mfc.GetRules(fam.table, chainOf(fam, cont1Name, cont1ID))
				is.NoErr(err)
				for i, rule := range got {
					if hasAcceptOrQueueVerdict(rule) && !isICMPv6(rule) {
						t.Errorf("%s rule %d accepts traffic although the rules are invalid", fam, i)
					}
				}
			}
		})
	}
}

// TestInvalidContainerRuleIsolatesAndRecordsContainer: a rule that names
// a container without whalewall enabled is invalid. The container must
// end up isolated, and known to whalewall so that its chain is removed
// again when it stops.
func TestInvalidContainerRuleIsolatesAndRecordsContainer(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	env := newIPv6TestEnv(t, true, false)
	mock, ok := env.r.dockerCli.(*mockDockerClient)
	is.True(ok)

	target := dualStackContainer(cont2ID, cont2Name, map[string]string{}, nil)
	delete(target.Config.Labels, enabledLabel) // the target is not managed
	mock.containers = append(mock.containers, target)

	rules := fmt.Sprintf("output:\n  - network: %s\n    container: %s\n    proto: tcp\n    dst_ports: [80]\n", netDefault, cont2Name)
	c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: rules}, nil)
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))

	got, err := env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.NoErr(err)
	for i, rule := range got {
		if hasAcceptOrQueueVerdict(rule) {
			t.Errorf("rule %d accepts traffic although the rules are invalid", i)
		}
	}
	is.True(len(got) > 0)

	exists, err := env.r.containerExists(context.Background(), env.r.db, cont1ID)
	is.NoErr(err)
	is.True(exists) // the container is known

	// stopping the container removes its chain
	is.NoErr(env.r.deleteContainerRules(context.Background(), cont1ID, cont1Name))
	_, err = env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.True(err != nil)
}

// TestRouterAdvertisementsAreNotAllowed checks the ICMPv6 types a managed
// container's chain accepts. Router advertisements (134) and redirects
// (137) from a container would let it take over the IPv6 configuration of
// the other containers on its network.
func TestRouterAdvertisementsAreNotAllowed(t *testing.T) {
	t.Parallel()

	allowed := make(map[byte]bool)
	for _, rule := range createICMPv6Rules(&nftables.Chain{Table: family6.table}, "id") {
		var low, high byte = 0, 255
		for _, e := range rule.Exprs {
			c, ok := e.(*expr.Cmp)
			if !ok || len(c.Data) != 1 || c.Data[0] == unix.IPPROTO_ICMPV6 {
				continue
			}
			switch c.Op {
			case expr.CmpOpEq:
				low, high = c.Data[0], c.Data[0]
			case expr.CmpOpGte:
				low = c.Data[0]
			case expr.CmpOpLte:
				high = c.Data[0]
			}
		}
		for typ := int(low); typ <= int(high); typ++ {
			allowed[byte(typ)] = true
		}
	}

	for _, typ := range []byte{133, 135, 136, 2} {
		if !allowed[typ] {
			t.Errorf("ICMPv6 type %d is not allowed but IPv6 needs it", typ)
		}
	}
	for typ := range 256 {
		switch byte(typ) {
		case 2, 133, 135, 136:
		default:
			if allowed[byte(typ)] {
				t.Errorf("ICMPv6 type %d is allowed", typ)
			}
		}
	}
}

// TestAllowedAddressesPerRuleAreCapped: a wildcard rule lets a container
// resolve names it controls, each with many addresses. The kernel keeps
// every one until its TTL ends, so the number must be limited.
func TestAllowedAddressesPerRuleAreCapped(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	env := newIPv6TestEnv(t, true, true)
	c := dualStackContainer(cont1ID, cont1Name, map[string]string{
		rulesLabel: `
output:
  - domains: ["**.wild.example"]
    proto: tcp
    dst_ports: [443]
  - domains: ["exact.example"]
    proto: tcp
    dst_ports: [8443]`,
	}, []string{dummyDNS})
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))
	p := env.dns.policy(cont1Addr)
	is.True(p != nil)

	next := 0
	batch := func() []dnsproxy.Resolved {
		out := make([]dnsproxy.Resolved, 0, 64)
		for range 64 {
			next++
			out = append(out, dnsproxy.Resolved{
				Addr: netip.AddrFrom4([4]byte{10, byte(next >> 16), byte(next >> 8), byte(next)}),
				TTL:  time.Hour,
			})
		}
		return out
	}

	var failedAt int
	for i := range 200 {
		if err := p.Allow(context.Background(), "x.wild.example", batch()); err != nil {
			is.True(errors.Is(err, errTooManyAddrs))
			failedAt = i
			break
		}
	}
	is.True(failedAt != 0)                  // the flood was stopped
	is.True(failedAt*64 <= maxSetAddrs)     // after no more than the limit
	is.True(failedAt*64 > maxSetAddrs-64*2) // and not long before it
	env.refresh()
	set := env.mfc.tables[filterTableName].Sets[domainSetName(cont1ID, 0, family4)]
	is.True(len(set) <= maxSetAddrs)

	// the other rule has its own budget
	is.NoErr(p.Allow(context.Background(), "exact.example", batch()))

	// addresses that are already allowed don't count again
	again := []dnsproxy.Resolved{{Addr: netip.AddrFrom4([4]byte{10, 0, 0, 1}), TTL: time.Hour}}
	is.NoErr(p.Allow(context.Background(), "x.wild.example", again))

	// a name only opens the rule that lists it
	env.refresh()
	exact := env.mfc.tables[filterTableName].Sets[domainSetName(cont1ID, 1, family4)]
	is.Equal(len(exact), 64)
}

// TestOnlyTheFirstYAMLDocumentIsUsed: as before, a second document in the
// label is ignored; it must not be able to widen the rules.
func TestOnlyTheFirstYAMLDocumentIsUsed(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	env := newIPv6TestEnv(t, true, false)
	rules := "output:\n  - proto: tcp\n    dst_ports: [80]\n---\noutput:\n  - ips: [0.0.0.0/0]\n    proto: tcp\n    dst_ports: [1-65535]\n"
	c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: rules}, nil)
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))

	got, err := env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.NoErr(err)
	var accepting int
	for _, rule := range got {
		if !hasAcceptOrQueueVerdict(rule) {
			continue
		}
		accepting++
		for _, e := range rule.Exprs {
			if c, ok := e.(*expr.Cmp); ok && bytes.Equal(c.Data, []byte{0xff, 0xff}) {
				t.Error("a rule of the second document was applied")
			}
		}
	}
	is.True(accepting > 0) // the first document applies
}

// The tests below check that without any of the new options whalewall
// behaves as it did before they existed.

func TestDefaultsKeepInvalidRulesUnmanaged(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	env := newTestEnv(t, true, false) // no options
	c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: "output:\n  - bogus: true\n"}, nil)

	err := env.r.createContainerRules(context.Background(), c, true)
	is.True(err != nil) // reported
	// and no rules were created, like before
	_, err = env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.True(errors.Is(err, syscall.ENOENT))

	// the same rules isolate the container if asked to
	env = newTestEnv(t, true, false, WithIsolateInvalidRules())
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))
	got, err := env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.NoErr(err)
	is.True(len(got) > 0)
}

func TestDefaultsDoNotTouchIPv6(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	// Docker has IPv6 chains, the container has an IPv6 address
	env := newTestEnv(t, true, false) // no options
	rules := "output:\n  - proto: tcp\n    dst_ports: [443]\n"
	c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: rules}, nil)
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))

	_, err := env.mfc.GetRules(family4.table, chainOf(family4, cont1Name, cont1ID))
	is.NoErr(err) // IPv4 is managed
	_, err = env.mfc.GetRules(family6.table, chainOf(family6, cont1Name, cont1ID))
	is.True(err != nil) // IPv6 is not
	is.True(!env.r.ipv6Ready)

	// with -ipv6 it is
	env = newTestEnv(t, true, false, WithIPv6())
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))
	_, err = env.mfc.GetRules(family6.table, chainOf(family6, cont1Name, cont1ID))
	is.NoErr(err)
}

func TestDefaultsDoNotCreateIPv6BaseRulesAtStart(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	env := newTestEnv(t, true, false) // no options
	chains, err := env.mfc.ListChainsOfTableFamily(nftables.TableFamilyIPv6)
	is.NoErr(err)
	for _, ch := range chains {
		if ch.Name == whalewallChainName {
			t.Error("the whalewall chain exists in the IPv6 table")
		}
	}
}

func TestContainerWithoutNetworkDoesNotFail(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	env := newTestEnv(t, false, false)
	c := dualStackContainer(cont1ID, cont1Name, map[string]string{}, nil)
	c.NetworkSettings.Networks = map[string]*network.EndpointSettings{}
	// like before, this is not an error (the container uses another
	// container's network); an error is logged
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))
}
