package main

import (
	"os"
	"strings"

	"go.uber.org/zap"
)

// kernelSetting reads a sysctl through /proc/sys.
func kernelSetting(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	return strings.TrimSpace(string(b)), true
}

// checkKernelSettings warns about host settings that silently make the
// firewall ineffective. It has to run before landlock rules are applied.
func checkKernelSettings(logger *zap.Logger) {
	// without br_netfilter, traffic between containers on the same
	// bridge never reaches the IP hooks whalewall's rules are in
	if v, ok := kernelSetting("/proc/sys/net/bridge/bridge-nf-call-iptables"); !ok {
		logger.Warn("the br_netfilter kernel module is not loaded: traffic between containers on the same Docker network is not filtered, load it with 'modprobe br_netfilter'")
	} else if v != "1" {
		logger.Warn("net.bridge.bridge-nf-call-iptables is not 1: traffic between containers on the same Docker network is not filtered", zap.String("value", v))
	}
	// connection tracking helpers (FTP, ...) open "related" connections
	// that the rules accept without matching the destination
	if v, ok := kernelSetting("/proc/sys/net/netfilter/nf_conntrack_helper"); ok && v == "1" {
		logger.Warn("net.netfilter.nf_conntrack_helper is 1: connection tracking helpers can open connections that firewall rules did not allow, set it to 0")
	}
}
