package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"

	"github.com/capnspacehook/whalewall"
)

const dbFilename = "db.sqlite"

func main() {
	os.Exit(mainRetCode())
}

func mainRetCode() int {
	clearRules := flag.Bool("clear", false, "remove all firewall rules created by whalewall")
	dataDir := flag.String("d", ".", "directory to store state in")
	debugLogs := flag.Bool("debug", false, "enable debug logging")
	logPath := flag.String("l", "stdout", "path to log to")
	timeout := flag.Duration("t", 10*time.Second, "timeout for Docker API requests")
	dnsEnabled := flag.Bool("dns", false, "enable rules that allow traffic by domain name; starts a DNS resolver that managed containers' DNS queries are redirected to")
	dnsPort := flag.Uint("dns-port", 5353, "port the DNS resolver listens on, on the gateway address of each managed network")
	dnsUpstream := flag.String("dns-upstream", "", "comma-separated host:port list of upstream DNS servers; defaults to the servers in /etc/resolv.conf")
	dnsMinTTL := flag.Duration("dns-min-ttl", 30*time.Second, "minimum time an address resolved from an allowed domain stays allowed")
	dnsMaxTTL := flag.Duration("dns-max-ttl", time.Hour, "maximum time an address resolved from an allowed domain stays allowed, whatever the TTL of the record is")
	dnsGrace := flag.Duration("dns-grace", 5*time.Second, "time added to the TTL of every resolved address")
	ipv6 := flag.Bool("ipv6", false, "manage the IPv6 traffic of containers that have an IPv6 address; needs Docker's ip6tables support")
	isolateInvalid := flag.Bool("isolate-invalid", false, "drop all traffic of a container whose rules are invalid; by default a container with invalid rules gets no rules and is not restricted")
	displayVersion := flag.Bool("version", false, "print version and build information and exit")
	flag.Parse()

	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Println("build information not found")
		return 1
	}

	if *displayVersion {
		printVersionInfo(info)
		return 0
	}

	// build logger
	logCfg := zap.NewProductionConfig()
	logCfg.OutputPaths = []string{*logPath}
	if *debugLogs {
		logCfg.Level.SetLevel(zap.DebugLevel)
	}
	logCfg.EncoderConfig.TimeKey = "time"
	logCfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	logCfg.DisableCaller = true

	logger, err := logCfg.Build()
	if err != nil {
		log.Printf("error creating logger: %v", err)
		return 1
	}

	// check if kernel version is new enough to support used nftables features
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		logger.Error("error getting kernel version", zap.Error(err))
	} else {
		kernelVer := parseCStr(uname.Release[:])
		var major, minor int
		_, err := fmt.Fscanf(strings.NewReader(kernelVer), "%d.%d", &major, &minor)
		if err != nil {
			logger.Error("error parsing kernel version", zap.Error(err))
			// minimum kernel version is around 5.10
		} else if major < 5 || (major == 5 && minor < 10) {
			logger.Sugar().Warnf("current kernel version %q is unsupported, 5.10 or greater is required; whalewall will probably not work correctly", kernelVer)
		}
	}

	// warn about host settings that make the rules ineffective; this has to
	// happen before privileges are dropped as it reads from /proc/sys
	checkKernelSettings(logger)

	// create rule manager and drop unneeded privileges
	dataDirAbs, err := filepath.Abs(*dataDir)
	if err != nil {
		logger.Error("error getting absolute path", zap.String("path", *dataDir), zap.Error(err))
		return 1
	}
	sqliteFile := filepath.Join(dataDirAbs, dbFilename)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// every flag that adds behavior is off by default and becomes an
	// option; without any whalewall behaves like previous versions
	var opts []whalewall.Option
	if *ipv6 {
		opts = append(opts, whalewall.WithIPv6())
	}
	if *isolateInvalid {
		opts = append(opts, whalewall.WithIsolateInvalidRules())
	}
	if *dnsEnabled {
		// flag.Uint is wider than a port
		if *dnsPort == 0 || *dnsPort > 65535 {
			logger.Error("invalid DNS port", zap.Uint("dns.port", *dnsPort))
			return 1
		}
		dnsOpts := whalewall.DNSOptions{
			Port:   uint16(*dnsPort),
			MinTTL: *dnsMinTTL,
			MaxTTL: *dnsMaxTTL,
			Grace:  *dnsGrace,
		}
		// without upstreams the resolver uses the host's /etc/resolv.conf
		if *dnsUpstream != "" {
			for _, up := range strings.Split(*dnsUpstream, ",") {
				dnsOpts.Upstreams = append(dnsOpts.Upstreams, strings.TrimSpace(up))
			}
		}
		opts = append(opts, whalewall.WithDNS(dnsOpts))
	}

	r, err := whalewall.NewRuleManager(ctx, logger, sqliteFile, *timeout, opts...)
	if err != nil {
		logger.Error("error initializing", zap.Error(err))
	}

	if !restrictPrivileges(logger, sqliteFile, *logPath) {
		return 1
	}

	// remove all created firewall rules if the user asked to clear
	if *clearRules {
		logger.Info("clearing rules")
		if err := r.Clear(ctx, sqliteFile); err != nil {
			logger.Error("error clearing rules", zap.Error(err))
			return 1
		}
		return 0
	}

	// log current version/commit
	versionFields := []zap.Field{
		zap.String("version", version),
	}
	for _, buildSetting := range info.Settings {
		if buildSetting.Key == "vcs.revision" {
			versionFields = append(versionFields, zap.String("commit", buildSetting.Value))
		}
		if buildSetting.Key == "CGO_ENABLED" && buildSetting.Value != "0" {
			logger.Fatal("this binary was built with cgo and will not function as intended; rebuild with cgo disabled")
		}
	}
	logger.Info("starting whalewall", versionFields...)

	// start managing firewall rules
	if err = r.Start(ctx); err != nil {
		logger.Error("error starting", zap.Error(err))
		if errors.Is(err, syscall.EPERM) {
			logger.Info("whalewall seems to lack required permissions, is the NET_ADMIN capability set?")
		}
		return 1
	}

	select {
	case <-ctx.Done():
	case <-r.Done():
	}
	logger.Info("shutting down")
	r.Stop()

	return 0
}

// TODO: test with docker with TLS
func restrictPrivileges(logger *zap.Logger, sqliteFile, logPath string) bool {
	// only allow needed files to be read/written to
	// sqlite database needs read/write access
	allowedPaths := []landlock.PathOpt{
		landlock.RODirs(filepath.Dir(sqliteFile)),
		landlock.RWFiles(
			sqliteFile,
			sqliteFile+"-wal",
			sqliteFile+"-shm",
		),
	}
	// if we are logging to a file we need to write to it
	if logPath != "stdout" && logPath != "stderr" {
		allowedPaths = append(allowedPaths,
			landlock.PathAccess(llsyscall.AccessFSWriteFile, logPath),
		)
	}
	// Go's networking stack/runtime will read the following files if
	// they are available, which they may not be if we are in a container
	allowedPaths = append(allowedPaths,
		landlock.PathAccess(
			llsyscall.AccessFSReadFile,
			"/etc/protocols",
			"/etc/services",
			"/etc/localtime",
			"/etc/nsswitch.conf",
			"/etc/resolv.conf",
			"/etc/hosts",
		).IgnoreIfMissing(),
	)

	err := landlock.V1.RestrictPaths(
		allowedPaths...,
	)
	if err != nil {
		if strings.HasPrefix(err.Error(), "missing kernel Landlock support") {
			logger.Info("unable to apply landlock rules, missing kernel support")
		} else {
			logger.Fatal("error creating landlock rules", zap.NamedError("error", err))
		}
	} else {
		logger.Info("applied landlock rules")
	}

	// block unneeded syscalls
	numAllowedSyscalls, err := installSeccompFilters()
	if err != nil {
		logger.Error("error setting seccomp rules", zap.Error(err))
		return false
	}
	logger.Info("applied seccomp filters", zap.Int("syscalls.allowed", numAllowedSyscalls))

	return true
}

func parseCStr(cstr []byte) string {
	p := make([]byte, 0, len(cstr))
	for _, c := range cstr {
		if c == 0x00 {
			break
		}
		p = append(p, c)
	}

	return string(p)
}
