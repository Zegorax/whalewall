package whalewall

import (
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestParseDomainPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    string
		kind    domainKind
		wantErr bool
	}{
		{in: "example.com", want: "example.com", kind: domainExact},
		{in: "Example.COM.", want: "example.com", kind: domainExact},
		{in: "a.b.example.com", want: "a.b.example.com", kind: domainExact},
		{in: "*.example.com", want: "*.example.com", kind: domainWildcard},
		{in: "**.example.com", want: "**.example.com", kind: domainNested},
		{in: "*.Example.com.", want: "*.example.com", kind: domainWildcard},
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
		{in: ".example.com", wantErr: true},
		{in: "a..example.com", wantErr: true},
		{in: strings.Repeat("a", 64) + ".com", wantErr: true},
		{in: strings.Repeat("a.", 130) + "com", wantErr: true},
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
			pattern: "example.com",
			match:   []string{"example.com", "EXAMPLE.com.", "Example.Com"},
			noMatch: []string{"a.example.com", "evilexample.com", "example.com.evil.net", "com", ""},
		},
		{
			pattern: "*.example.com",
			match:   []string{"a.example.com", "A.Example.com.", "x-y.example.com"},
			noMatch: []string{"example.com", "a.b.example.com", "evilexample.com", ".example.com", "a.example.com.evil.net", "aexample.com"},
		},
		{
			pattern: "**.example.com",
			match:   []string{"a.example.com", "a.b.example.com", "a.b.c.d.e.example.com"},
			noMatch: []string{"example.com", "evilexample.com", ".example.com", "a.example.com.evil.net", "com"},
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

	var list domainsList
	for _, s := range []string{"example.com", "**.example.com", "*.other.net"} {
		p, err := parseDomainPattern(s)
		is.NoErr(err)
		list = append(list, p)
	}

	is.True(list.matches("example.com"))
	is.True(list.matches("a.b.example.com"))
	is.True(list.matches("a.other.net"))
	is.True(!list.matches("a.b.other.net"))
	is.True(!list.matches("other.net"))
}

func TestDomainPatternRoundTrip(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	for _, s := range []string{"example.com", "*.example.com", "**.example.com"} {
		p, err := parseDomainPattern(s)
		is.NoErr(err)
		b, err := p.MarshalBinary()
		is.NoErr(err)
		var got domainPattern
		is.NoErr(got.UnmarshalBinary(b))
		is.Equal(got, p)
	}
}
