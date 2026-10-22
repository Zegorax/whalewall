package whalewall

import (
	"strings"

	"github.com/docker/docker/api/types/container"
)

const (
	capNetRaw   = "NET_RAW"
	capNetAdmin = "NET_ADMIN"
	capSysAdmin = "SYS_ADMIN"
	capAll      = "ALL"
)

// capHas reports whether a list of capabilities names capability, with or
// without the CAP_ prefix, or ALL.
func capHas(caps []string, name string) bool {
	for _, c := range caps {
		c = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		if c == name || c == capAll {
			return true
		}
	}

	return false
}

// capWarning is something a container's capabilities allow. Severe ones
// give the container full control of its networking; the default
// capabilities (NET_RAW) are common enough to only be an informational
// message.
type capWarning struct {
	msg    string
	severe bool
}

// capabilityWarnings returns what a container's capabilities let it do
// to get around the rules of its own or of other containers. None of this
// can be prevented from the host's firewall, so the administrator is
// told.
func capabilityWarnings(hc *container.HostConfig) []capWarning {
	if hc == nil {
		return nil
	}

	var warnings []capWarning
	switch {
	case hc.Privileged:
		warnings = append(warnings, capWarning{"the container is privileged and can change its own network configuration, firewall rules do not restrict it", true})
	case capHas(hc.CapAdd, capNetAdmin) || capHas(hc.CapAdd, capSysAdmin):
		warnings = append(warnings, capWarning{"the container has NET_ADMIN or SYS_ADMIN and can change its own addresses to get around its rules", true})
	case !capHas(hc.CapDrop, capNetRaw) || capHas(hc.CapAdd, capNetRaw):
		warnings = append(warnings, capWarning{"the container keeps NET_RAW and can forge source addresses of other containers on its networks to get around its rules, add cap_drop: [NET_RAW]", false})
	}

	return warnings
}
