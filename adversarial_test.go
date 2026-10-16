package whalewall

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/matryer/is"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

// refMatches is a deliberately simple reference implementation of the
// documented matching rules, built from labels instead of suffix tricks.
func refMatches(kind domainKind, suffix, name string) bool {
	nl := strings.Split(name, ".")
	sl := strings.Split(suffix, ".")
	switch kind {
	case domainExact:
		return name == suffix
	case domainWildcard:
		if len(nl) != len(sl)+1 {
			return false
		}
	case domainNested:
		if len(nl) < len(sl)+1 {
			return false
		}
	}
	tail := nl[len(nl)-len(sl):]
	for i := range sl {
		if tail[i] != sl[i] {
			return false
		}
	}
	return nl[0] != "" // the labels above the suffix must not be empty
}

func TestDomainMatchingAgainstReference(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	suffixes := []string{"example.com", "a.example.com", "com", "x-y.z.example.org"}
	prefixes := []string{"", "a.", "b.", "a.b.", "a.b.c.", "x.", "evil", "evil.", ".", "-", "a-"}
	for _, suffix := range suffixes {
		for _, kind := range []domainKind{domainExact, domainWildcard, domainNested} {
			pat := domainPattern{kind: kind, suffix: suffix}
			for _, prefix := range prefixes {
				for _, tail := range []string{"", ".", ".net"} {
					for _, base := range []string{suffix, strings.ToUpper(suffix), "x" + suffix, suffix + "x"} {
						name := prefix + base + tail
						want := refMatches(kind, suffix, strings.ToLower(strings.TrimSuffix(name, ".")))
						got := domainsList{pat}.matches(name)
						if got != want {
							t.Errorf("%s matching %q: got %v, want %v", pat, name, got, want)
						}
					}
				}
			}
		}
	}
	is.True(true)
}

func TestDomainMatchingRejectsFoldedUnicode(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	p, err := parseDomainPattern("kube.example.com")
	is.NoErr(err)
	list := domainsList{p}
	is.True(list.matches("kube.example.com"))
	is.True(list.matches("KUBE.EXAMPLE.COM"))
	for _, name := range []string{
		"Kube.example.com", // Kelvin sign, Unicode lower-cases it to "k"
		"kube.example.com​",
		"kıbe.example.com",
		"kube.examplе.com", // Cyrillic e
		"kube.example.com\x00",
		"kube\x00.example.com",
	} {
		is.True(!list.matches(name)) // name
	}

	wild, err := parseDomainPattern("*.example.com")
	is.NoErr(err)
	is.True(!(domainsList{wild}).matches("K.example.com.evil"))
	is.True((domainsList{wild}).matches("k.example.com"))
}

func FuzzParseDomainPattern(f *testing.F) {
	for _, seed := range []string{"example.com", "*.example.com", "**.example.com", "", "*", "a.*.b", "K", "xn--bcher-kva.example", "a..b", strings.Repeat("a", 300)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := parseDomainPattern(s)
		if err != nil {
			return
		}
		// a parsed pattern is canonical: parsing its text gives the same
		again, err := parseDomainPattern(p.String())
		if err != nil || again != p {
			t.Fatalf("pattern %q is not stable: %v %v", p, again, err)
		}
		// a pattern never matches a name it is not a suffix of, and never
		// matches its own suffix when it has a wildcard
		list := domainsList{p}
		if p.kind != domainExact && list.matches(p.suffix) {
			t.Fatalf("wildcard %q matches its own suffix", p)
		}
		if p.kind == domainExact && !list.matches(p.suffix) {
			t.Fatalf("exact %q does not match itself", p)
		}
		for _, c := range p.suffix {
			if c > 0x7f {
				t.Fatalf("pattern %q is not ASCII", p)
			}
		}
	})
}

func FuzzDomainMatches(f *testing.F) {
	for _, seed := range []string{"a.example.com", "example.com", "Kube.example.com", "A.B.EXAMPLE.COM.", "", ".", "..", "a..example.com"} {
		f.Add(seed)
	}
	pats := make(domainsList, 0, 3)
	for _, s := range []string{"example.com", "*.example.com", "**.example.org"} {
		p, err := parseDomainPattern(s)
		if err != nil {
			f.Fatal(err)
		}
		pats = append(pats, p)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if !pats.matches(name) {
			return
		}
		// whatever matched must really be below one of the suffixes, as
		// plain ASCII
		for i := 0; i < len(name); i++ {
			if name[i] > 0x7f {
				t.Fatalf("non-ASCII name %q matched", name)
			}
		}
		lower := strings.ToLower(strings.TrimSuffix(name, "."))
		if lower != "example.com" && !strings.HasSuffix(lower, ".example.com") && !strings.HasSuffix(lower, ".example.org") {
			t.Fatalf("%q matched but is not below a pattern's suffix", name)
		}
		if strings.Contains(lower, "..") || strings.HasPrefix(lower, ".") {
			t.Fatalf("%q matched with an empty label", name)
		}
	})
}

// A container's labels are controlled by whoever can start containers.
// Parsing them must not be a way to crash or stall whalewall.
func TestHostileRulesLabels(t *testing.T) {
	t.Parallel()

	billion := func() string {
		var b strings.Builder
		b.WriteString("output:\n  - proto: tcp\n    dst_ports: &l0 [")
		b.WriteString(strings.Repeat("1,", 8) + "1]\n")
		for i := 1; i < 12; i++ {
			fmt.Fprintf(&b, "    x%d: &l%d [%s]\n", i, i, strings.Repeat(fmt.Sprintf("*l%d,", i-1), 9)+fmt.Sprintf("*l%d", i-1))
		}
		return b.String()
	}

	tests := map[string]string{
		"alias bomb":       billion(),
		"deep nesting":     strings.Repeat("[", 20000) + strings.Repeat("]", 20000),
		"huge scalar":      "output:\n  - domains: [\"" + strings.Repeat("a", 1<<20) + ".com\"]\n    proto: tcp\n    dst_ports: [443]",
		"many domains":     "output:\n  - domains: [" + strings.Repeat("\"a.example.com\",", 50000) + "\"b.example.com\"]\n    proto: tcp\n    dst_ports: [443]",
		"many rules":       "output:\n" + strings.Repeat("  - ips: [1.1.1.1]\n    proto: tcp\n    dst_ports: [443]\n", 20000),
		"binary garbage":   "\x00\x01\x02\xff\xfe output: [\x00",
		"tabs":             "output:\n\t- proto: tcp",
		"duplicate keys":   "output: []\noutput: []",
		"unknown key":      "output:\n  - domains: [example.com]\n    proto: tcp\n    dst_ports: [443]\n    run: rm -rf /",
		"merge key":        "x: &a {proto: tcp}\noutput:\n  - <<: *a\n    domains: [a.com]",
		"custom tag":       "output: !!python/object/apply:os.system [\"id\"]",
		"port overflow":    "output:\n  - domains: [a.com]\n    proto: tcp\n    dst_ports: [99999999999999999999]",
		"negative port":    "output:\n  - domains: [a.com]\n    proto: tcp\n    dst_ports: [-1]",
		"port zero":        "output:\n  - domains: [a.com]\n    proto: tcp\n    dst_ports: [0]",
		"inverted range":   "output:\n  - domains: [a.com]\n    proto: tcp\n    dst_ports: [500-10]",
		"proto injection":  "output:\n  - domains: [a.com]\n    proto: \"tcp; drop\"\n    dst_ports: [443]",
		"null domains":     "output:\n  - domains: [null, ~, '']\n    proto: tcp\n    dst_ports: [443]",
		"domain as number": "output:\n  - domains: [1234]\n    proto: tcp\n    dst_ports: [443]",
	}
	for name, label := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			done := make(chan struct{})
			var (
				cfg config
				err error
			)
			go func() {
				defer close(done)
				dec := yaml.NewDecoder(strings.NewReader(label))
				dec.KnownFields(true)
				err = dec.Decode(&cfg)
				if err == nil {
					err = validateConfig(cfg)
				}
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("parsing the label took more than 10 seconds")
			}

			// the ones that parse have to be valid ones; none of the
			// hostile inputs may produce a rule that allows more than asked
			if err == nil {
				for _, r := range cfg.Output {
					if len(r.Domains) != 0 && (r.Proto == invalidProto || len(r.DstPorts) == 0) {
						t.Fatalf("domain rule without proto and ports was accepted: %+v", r)
					}
					for _, d := range r.Domains {
						if d.suffix == "" {
							t.Fatalf("empty domain was accepted")
						}
					}
				}
			}
		})
	}
}

// Spoofed or stale resolver state must not survive container removal.
func TestResolverStateIsRemovedWithContainer(t *testing.T) {
	t.Parallel()

	env := newIPv6TestEnv(t, true, true)
	is := env.is

	c := dualStackContainer(cont1ID, cont1Name, map[string]string{rulesLabel: `
output:
  - domains: ["**.example.com"]
    proto: tcp
    dst_ports: [443]`}, []string{dummyDNS})
	is.NoErr(env.r.createContainerRules(context.Background(), c, true))
	p := env.dns.policy(cont1Addr)
	is.True(p != nil)
	// the host's addresses are rejected as answers
	is.True(p.Reject(gatewayAddr))
	is.True(p.Reject(gatewayAddr6))
	is.True(!p.Reject(netip.MustParseAddr("203.0.113.9")))
	is.True(!p.Reject(cont1Addr))

	is.NoErr(env.r.deleteContainerRules(context.Background(), cont1ID, cont1Name))
	// the address can be reused by another container without inheriting
	// a policy
	is.True(env.dns.policy(cont1Addr) == nil)
	is.True(env.dns.policy(cont1Addr6) == nil)
	is.Equal(len(env.dns.listening), 0)

	// and a second container with the same address gets only its own
	c2 := dualStackContainer(cont2ID, cont2Name, map[string]string{rulesLabel: `
output:
  - domains: ["only.other.net"]
    proto: tcp
    dst_ports: [443]`}, []string{dummyDNS})
	is.NoErr(env.r.createContainerRules(context.Background(), c2, true))
	p2 := env.dns.policy(cont1Addr)
	is.True(p2 != nil)
	is.True(!p2.Match("a.example.com"))
	is.True(p2.Match("only.other.net"))
}

// Whatever the configuration, a container chain must never contain an
// accept rule that isn't tied to the container's own address and to a
// protocol, otherwise one rule could open traffic of other containers or
// of every protocol.
func TestEveryAcceptRuleIsScoped(t *testing.T) {
	t.Parallel()

	configs := map[string]string{
		"domains": `
output:
  - domains: [a.example.com, "*.example.net", "**.example.org"]
    proto: tcp
    dst_ports: [443, 8000-9000]
  - domains: [b.example.com]
    proto: udp
    dst_ports: [53]
    log_prefix: dns`,
		"ips and ports": `
output:
  - ips: [1.1.1.1, 2001:db8::1, 10.0.0.0/8, 2001:db8:1::/48]
    proto: tcp
    dst_ports: [80, 443]
  - proto: udp
    dst_ports: [53]`,
		"queues": `
output:
  - domains: [a.example.com]
    proto: tcp
    dst_ports: [443]
    verdict:
      queue: 3
      input_est_queue: 4
      output_est_queue: 5
  - proto: tcp
    dst_ports: [80]
    verdict:
      queue: 3
      input_est_queue: 3
      output_est_queue: 3`,
		"mapped ports": `
mapped_ports:
  localhost:
    allow: true
  external:
    allow: true
output:
  - domains: [a.example.com]
    proto: tcp
    dst_ports: [443]`,
		"empty": "",
	}

	for name, rules := range configs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newIPv6TestEnv(t, true, true)
			is := env.is
			labels := map[string]string{}
			if rules != "" {
				labels[rulesLabel] = rules
			}
			c := dualStackContainer(cont1ID, cont1Name, labels, []string{dummyDNS})
			is.NoErr(env.r.createContainerRules(context.Background(), c, true))

			for _, fam := range families {
				chain := chainOf(fam, cont1Name, cont1ID)
				rules, err := env.mfc.GetRules(fam.table, chain)
				is.NoErr(err)
				is.True(len(rules) > 0)

				addr := cont1Addr.AsSlice()
				if fam.v6 {
					addr = cont1Addr6.AsSlice()
				}
				last := rules[len(rules)-1]
				is.True(isDropRule(last)) // the chain ends in the drop rule

				for i, rule := range rules[:len(rules)-1] {
					if !hasAcceptOrQueueVerdict(rule) {
						continue
					}
					if !matchesProto(rule) {
						t.Errorf("%s rule %d accepts without matching a protocol", fam, i)
					}
					if !matchesData(rule, addr) && !isICMPv6(rule) {
						t.Errorf("%s rule %d is not tied to the container address", fam, i)
					}
				}
			}
		})
	}
}

func hasAcceptOrQueueVerdict(r *nftables.Rule) bool {
	if len(r.Exprs) == 0 {
		return false
	}
	switch e := r.Exprs[len(r.Exprs)-1].(type) {
	case *expr.Verdict:
		return e.Kind == expr.VerdictAccept
	case *expr.Queue:
		return true
	}
	return false
}

func isDropRule(r *nftables.Rule) bool {
	if len(r.Exprs) == 0 {
		return false
	}
	v, ok := r.Exprs[len(r.Exprs)-1].(*expr.Verdict)
	return ok && v.Kind == expr.VerdictDrop
}

func matchesProto(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyL4PROTO {
			return true
		}
	}
	return false
}

func matchesData(r *nftables.Rule, data []byte) bool {
	for _, e := range r.Exprs {
		if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpEq && bytes.Equal(c.Data, data) {
			return true
		}
	}
	return false
}

func isICMPv6(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpEq && bytes.Equal(c.Data, []byte{unix.IPPROTO_ICMPV6}) {
			return true
		}
	}
	return false
}
