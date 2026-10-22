package whalewall

import (
	"strings"
	"testing"

	"github.com/matryer/is"
	"gopkg.in/yaml.v3"
)

const errMutuallyExclusive = "mutually exclusive"

func TestConfigDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rules   string
		wantErr string
	}{
		{
			name: "exact, wildcard and nested",
			rules: `
output:
  - domains: [api.example.com, "*.example.net", "**.example.org"]
    proto: tcp
    dst_ports: [443]`,
		},
		{
			name: "domains with multiple ports",
			rules: `
output:
  - domains: [example.com]
    proto: udp
    dst_ports: [53, 5000-5010]`,
		},
		{
			name: "mid-name wildcard",
			rules: `
output:
  - domains: ["a.*.example.com"]
    proto: tcp
    dst_ports: [443]`,
			wantErr: "entire first label",
		},
		{
			name: "bare wildcard",
			rules: `
output:
  - domains: ["*"]
    proto: tcp
    dst_ports: [443]`,
			wantErr: "entire first label",
		},
		{
			name: "domains and ips",
			rules: `
output:
  - domains: [example.com]
    ips: [1.1.1.1]
    proto: tcp
    dst_ports: [443]`,
			wantErr: errMutuallyExclusive,
		},
		{
			name: "domains and container",
			rules: `
output:
  - domains: [example.com]
    network: default
    container: other
    proto: tcp
    dst_ports: [443]`,
			wantErr: errMutuallyExclusive,
		},
		{
			name: "domains and network",
			rules: `
output:
  - domains: [example.com]
    network: default
    proto: tcp
    dst_ports: [443]`,
			wantErr: errMutuallyExclusive,
		},
		{
			name: "domains without proto",
			rules: `
output:
  - domains: [example.com]
    dst_ports: [443]`,
			wantErr: `"proto" and "dst_ports" must be set`,
		},
		{
			name: "domains without ports",
			rules: `
output:
  - domains: [example.com]
    proto: tcp`,
			wantErr: "dst_ports",
		},
		{
			name: "only domains",
			rules: `
output:
  - domains: [example.com]`,
			wantErr: `"proto" and "dst_ports" must be set`,
		},
		{
			name: "empty domain",
			rules: `
output:
  - domains: [""]
    proto: tcp
    dst_ports: [443]`,
			wantErr: "domain is empty",
		},
		{
			name: "IPv6 addresses are valid in ips",
			rules: `
output:
  - ips: [2001:db8::1, 2001:db8:1::/48, "2001:db8:2::1-2001:db8:2::ff"]
    proto: tcp
    dst_ports: [443]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := is.New(t)

			var cfg config
			dec := yaml.NewDecoder(strings.NewReader(tt.rules))
			dec.KnownFields(true)
			err := dec.Decode(&cfg)
			if err == nil {
				err = validateConfig(cfg)
			}
			if tt.wantErr == "" {
				is.NoErr(err)
				return
			}
			is.True(err != nil)
			is.True(strings.Contains(err.Error(), tt.wantErr)) // error: err
		})
	}
}

func TestHasDomainRules(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	var cfg config
	is.True(!hasDomainRules(cfg))
	is.NoErr(yaml.Unmarshal([]byte("output:\n  - proto: tcp\n    dst_ports: [443]"), &cfg))
	is.True(!hasDomainRules(cfg))
	is.NoErr(yaml.Unmarshal([]byte("output:\n  - domains: [example.com]\n    proto: tcp\n    dst_ports: [443]"), &cfg))
	is.True(hasDomainRules(cfg))
}

func TestFamilyFilterIPs(t *testing.T) {
	t.Parallel()
	is := is.New(t)

	var cfg config
	is.NoErr(yaml.Unmarshal([]byte(`
output:
  - ips: [1.1.1.1, 2001:db8::1, 10.0.0.0/8, 2001:db8:1::/48, "10.1.0.1-10.1.0.9", "2001:db8:2::1-2001:db8:2::9"]
    proto: tcp
    dst_ports: [443]`), &cfg))
	ips := cfg.Output[0].IPs
	is.Equal(len(ips), 6)
	is.Equal(len(family4.filterIPs(ips)), 3)
	is.Equal(len(family6.filterIPs(ips)), 3)
}
