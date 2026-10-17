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
		{name: "default capabilities", hc: &container.HostConfig{}, want: "NET_RAW"},
		{name: "NET_RAW dropped", hc: &container.HostConfig{CapDrop: []string{"NET_RAW"}}},
		{name: "prefixed and lower case", hc: &container.HostConfig{CapDrop: []string{"cap_net_raw"}}},
		{name: "everything dropped", hc: &container.HostConfig{CapDrop: []string{"ALL"}}},
		{name: "everything dropped, NET_RAW added back", hc: &container.HostConfig{CapDrop: []string{"ALL"}, CapAdd: []string{"NET_RAW"}}, want: "NET_RAW"},
		{name: "NET_ADMIN", hc: &container.HostConfig{CapDrop: []string{"NET_RAW"}, CapAdd: []string{"NET_ADMIN"}}, want: "NET_ADMIN"},
		{name: "SYS_ADMIN", hc: &container.HostConfig{CapDrop: []string{"NET_RAW"}, CapAdd: []string{"SYS_ADMIN"}}, want: "SYS_ADMIN"},
		{name: "privileged", hc: &container.HostConfig{Privileged: true, CapDrop: []string{"ALL"}}, want: "privileged"},
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
			is.Equal(got[0].severe, tt.want != "NET_RAW")
		})
	}
}
