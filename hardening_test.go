package whalewall

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/matryer/is"
	"golang.org/x/sys/unix"
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

	manyDomains := make([]string, 5000)
	for i := range manyDomains {
		manyDomains[i] = fmt.Sprintf("h%d.example.com", i)
	}
	manyRules := strings.Repeat("  - proto: tcp\n    dst_ports: [80]\n", 1000)

	tests := map[string]string{
		"alias bomb":    aliases.String(),
		"huge label":    "output:\n  - proto: tcp\n    dst_ports: [80]\n# " + strings.Repeat("x", 1<<20),
		"many domains":  "output:\n  - domains: [" + strings.Join(manyDomains, ",") + "]\n    proto: tcp\n    dst_ports: [443]\n",
		"many rules":    "output:\n" + manyRules,
		"deep nesting":  "output:\n  - ips: " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n    proto: tcp\n    dst_ports: [80]\n",
		"long scalar":   "output:\n  - proto: tcp\n    dst_ports: [" + strings.Repeat("1", 1<<16) + "]\n",
		"many ports":    "output:\n  - proto: tcp\n    dst_ports: [" + strings.TrimSuffix(strings.Repeat("80,", 5000), ",") + "]\n",
		"binary":        "output:\n  - proto: tcp\x00\n",
		"multi doc":     "output:\n  - proto: tcp\n    dst_ports: [80]\n---\noutput:\n  - ips: [0.0.0.0/0]\n    proto: tcp\n    dst_ports: [1-65535]\n",
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
