package whalewall

import (
	"strings"
	"testing"

	"github.com/matryer/is"
)

const (
	domTLD     = "com"
	domExample = "example.com"
	domDeep    = "a.b.example.com"
	domWild    = "*.example.com"
	domNested  = "**.example.com"
	domDotted  = ".example.com"
	domSub     = "a.example.com"
	domEvil    = "evilexample.com"
)

func TestParseDomainPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    string
		kind    domainKind
		wantErr bool
	}{
		{in: domExample, want: domExample, kind: domainExact},
		{in: "Example.COM.", want: domExample, kind: domainExact},
		{in: domDeep, want: domDeep, kind: domainExact},
		{in: domWild, want: domWild, kind: domainWildcard},
		{in: domNested, want: domNested, kind: domainNested},
		{in: "*.Example.com.", want: domWild, kind: domainWildcard},
		{in: "bücher.example", want: "xn--bcher-kva.example", kind: domainExact},
		{in: "*.bücher.example", want: "*.xn--bcher-kva.example", kind: domainWildcard},
		{in: "localhost", want: "localhost", kind: domainExact},

		{in: "", wantErr: true},
		{in: ".", wantErr: true},
		{in: "*", wantErr: true},
		{in: "**", wantErr: true},
		{in: "*.", wantErr: true},
		{in: "**.", wantErr: true},
		{in: "***.example.com", wantErr: true},
		{in: "a.*.example.com", wantErr: true},
		{in: "*a.example.com", wantErr: true},
		{in: "a*.example.com", wantErr: true},
		{in: "*.*.example.com", wantErr: true},
		{in: "**.*.example.com", wantErr: true},
		{in: domDotted, wantErr: true},
		{in: "a..example.com", wantErr: true},
		{in: strings.Repeat("a", 64) + ".com", wantErr: true},
		{in: strings.Repeat("a.", 130) + domTLD, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			is := is.New(t)

			got, err := parseDomainPattern(tt.in)
			if tt.wantErr {
				is.True(err != nil)
				return
			}
			is.NoErr(err)
			is.Equal(got.String(), tt.want)
			is.Equal(got.kind, tt.kind)
		})
	}
}

func TestDomainMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{
			pattern: domExample,
			match:   []string{domExample, "EXAMPLE.com.", "Example.Com"},
			noMatch: []string{domSub, domEvil, "example.com.evil.net", domTLD, ""},
		},
		{
			pattern: domWild,
			match:   []string{domSub, "A.Example.com.", "x-y.example.com"},
			noMatch: []string{domExample, domDeep, domEvil, domDotted, "a.example.com.evil.net", "aexample.com"},
		},
		{
			pattern: domNested,
			match:   []string{domSub, domDeep, "a.b.c.d.e.example.com"},
			noMatch: []string{domExample, domEvil, domDotted, "a.example.com.evil.net", domTLD},
		},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			t.Parallel()
			is := is.New(t)

			p, err := parseDomainPattern(tt.pattern)
			is.NoErr(err)
			list := domainsList{p}
			for _, name := range tt.match {
				is.True(list.matches(name)) // should match
			}
			for _, name := range tt.noMatch {
				is.True(!list.matches(name)) // should not match
			}
		})
	}
}

func TestDomainsListMixed(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	list := make(domainsList, 0, 3)
	for _, s := range []string{domExample, domNested, "*.other.net"} {
		p, err := parseDomainPattern(s)
		is.NoErr(err)
		list = append(list, p)
	}

	is.True(list.matches(domExample))
	is.True(list.matches(domDeep))
	is.True(list.matches("a.other.net"))
	is.True(!list.matches("a.b.other.net"))
	is.True(!list.matches("other.net"))
}

func TestDomainPatternRoundTrip(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	for _, s := range []string{domExample, domWild, domNested} {
		p, err := parseDomainPattern(s)
		is.NoErr(err)
		b, err := p.MarshalBinary()
		is.NoErr(err)
		var got domainPattern
		is.NoErr(got.UnmarshalBinary(b))
		is.Equal(got, p)
	}
}
