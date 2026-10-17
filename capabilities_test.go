package whalewall

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/matryer/is"
)

func TestCapabilityWarnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hc   *container.HostConfig
		want string // substring of the only warning, empty for none
	}{
		{name: "nil", hc: nil},
		{name: "default capabilities", hc: &container.HostConfig{}, want: capNetRaw},
		{name: "NET_RAW dropped", hc: &container.HostConfig{CapDrop: []string{capNetRaw}}},
		{name: "prefixed and lower case", hc: &container.HostConfig{CapDrop: []string{"cap_net_raw"}}},
		{name: "everything dropped", hc: &container.HostConfig{CapDrop: []string{capAll}}},
		{name: "everything dropped, NET_RAW added back", hc: &container.HostConfig{CapDrop: []string{capAll}, CapAdd: []string{capNetRaw}}, want: capNetRaw},
		{name: capNetAdmin, hc: &container.HostConfig{CapDrop: []string{capNetRaw}, CapAdd: []string{capNetAdmin}}, want: capNetAdmin},
		{name: capSysAdmin, hc: &container.HostConfig{CapDrop: []string{capNetRaw}, CapAdd: []string{capSysAdmin}}, want: capSysAdmin},
		{name: "privileged", hc: &container.HostConfig{Privileged: true, CapDrop: []string{capAll}}, want: "privileged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := is.New(t)

			got := capabilityWarnings(tt.hc)
			if tt.want == "" {
				is.Equal(len(got), 0)
				return
			}
			is.Equal(len(got), 1)
			is.True(strings.Contains(got[0].msg, tt.want))
			is.Equal(got[0].severe, tt.want != capNetRaw)
		})
	}
}
