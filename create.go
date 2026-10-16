package whalewall

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/capnspacehook/whalewall/database"
)

const (
	hostNetworkName = "host"

	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
	composeContNumLabel = "com.docker.compose.container-number"

	chainPrefix = "whalewall-"

	srcAddrOffset = uint32(12)
	dstAddrOffset = uint32(16)
	srcPortOffset = uint32(0)
	dstPortOffset = uint32(2)

	stateNew    = expr.CtStateBitNEW
	stateEst    = expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	stateNewEst = stateNew | stateEst
)

var (
	localAddr     = netip.MustParseAddr("127.0.0.1")
	zeroUint32    = []byte{0, 0, 0, 0}
	acceptVerdict = &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
	dropVerdict = &expr.Verdict{
		Kind: expr.VerdictDrop,
	}
)

// createRules adds nftables rules for started containers.
func (r *RuleManager) createRules(ctx context.Context) {
	for c := range r.createCh {
		if err := r.createContainerRules(ctx, c.container, c.isNew); err != nil {
			r.logger.Error("error creating rules",
				zap.String("container.id", c.container.ID[:12]),
				zap.String("container.name", stripName(c.container.Name)),
				zap.Error(err),
			)
		}
	}
}

// famState holds the per-family state while rules for a container are
// being created.
type famState struct {
	fam       *family
	addrs     map[string][]byte
	chain     *nftables.Chain
	addrElems []nftables.SetElement
	// createdRules are the rules generated from the container's config
	createdRules []*nftables.Rule
	// domainSets are the sets created for output rules with domains,
	// by index of the rule
	domainSets map[int]*nftables.Set
}

// containerAddrs returns the IPv4 and IPv6 addresses of a container by
// network name.
func containerAddrs(networks map[string]*network.EndpointSettings, contName string) (map[string][]byte, map[string][]byte, error) {
	addrs4 := make(map[string][]byte, len(networks))
	addrs6 := make(map[string][]byte)
	for netName, netSettings := range networks {
		if netSettings.IPAddress == "" && netSettings.GlobalIPv6Address == "" {
			// produces the same error as before IPv6 was supported
			_, err := netip.ParseAddr(netSettings.IPAddress)
			return nil, nil, fmt.Errorf("error parsing IP of container: %q: %w", contName, err)
		}
		if netSettings.IPAddress != "" {
			addr, err := netip.ParseAddr(netSettings.IPAddress)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing IP of container: %q: %w", contName, err)
			}
			addrs4[netName] = addrBytes(addr)
		}
		if netSettings.GlobalIPv6Address != "" {
			addr, err := netip.ParseAddr(netSettings.GlobalIPv6Address)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing IPv6 address of container: %q: %w", contName, err)
			}
			addrs6[netName] = addrBytes(addr)
		}
	}

	return addrs4, addrs6, nil
}

// parseRules parses and validates the rules of a container.
func (r *RuleManager) parseRules(cfg string, container types.ContainerJSON, rulesCfg *config) error {
	dec := yaml.NewDecoder(strings.NewReader(cfg))
	dec.KnownFields(true)
	if err := dec.Decode(rulesCfg); err != nil {
		return fmt.Errorf("error parsing rules: %w", err)
	}
	if err := validateConfig(*rulesCfg); err != nil {
		return fmt.Errorf("error validating rules: %w", err)
	}
	if !hasDomainRules(*rulesCfg) {
		return nil
	}
	if !r.dnsEnabled {
		return errors.New(`rules use "domains" but DNS filtering is not enabled, start whalewall with the -dns flag`)
	}
	// Docker's embedded resolver sends queries for names it can't
	// resolve itself from the host's network namespace unless the
	// container has custom DNS servers set, in which case it sends them
	// from the container's. Queries from the host can't be attributed
	// to a container and so can't be filtered.
	if container.HostConfig == nil || len(container.HostConfig.DNS) == 0 {
		return errors.New(`rules use "domains" but the container has no "dns" option set, so Docker would resolve names outside of whalewall; set "dns" to any address, queries to it are redirected to whalewall`)
	}

	return nil
}

// createContainerRules creates nftables rules for a container.
func (r *RuleManager) createContainerRules(ctx context.Context, container types.ContainerJSON, isNew bool) (retErr error) {
	ctx, cleanup := r.containerTracker.StartCreatingContainer(ctx, container.ID)
	defer cleanup()

	contName := stripName(container.Name)
	logger := r.logger.With(zap.String("container.id", container.ID[:12]), zap.String("container.name", contName))
	logger.Info("creating rules", zap.Bool("container.is_new", isNew))

	// check that network settings are valid
	if container.NetworkSettings == nil {
		return fmt.Errorf("container %q has no network settings", contName)
	}
	if len(container.NetworkSettings.Networks) == 1 {
		if _, ok := container.NetworkSettings.Networks[hostNetworkName]; ok {
			return fmt.Errorf("container %q is using host networking, rules cannot be created for it", contName)
		}
	}

	// parse rules config if the rules label exists; if the label
	// does not exist, no rules will be added but all traffic to
	// and from the container will still be dropped
	var rulesCfg config
	cfg, configExists := container.Config.Labels[rulesLabel]
	if configExists {
		// If the rules are invalid the container is isolated completely
		// instead of being left unmanaged.
		if err := r.parseRules(cfg, container, &rulesCfg); err != nil {
			logger.Error("invalid rules, all traffic of the container is dropped", zap.Error(err))
			rulesCfg = config{}
		}
	}

	// ensure specified networks and containers in rules are valid
	addrs4, addrs6, err := containerAddrs(container.NetworkSettings.Networks, contName)
	if err != nil {
		return err
	}
	// allNets has an entry for every network of the container
	allNets := make(map[string][]byte, len(container.NetworkSettings.Networks))
	var states []*famState
	if len(addrs4) != 0 {
		states = append(states, &famState{fam: family4, addrs: addrs4})
		maps.Copy(allNets, addrs4)
	}
	if len(addrs6) != 0 {
		if err := r.ensureIPv6BaseRules(); err != nil {
			return fmt.Errorf("container %q has an IPv6 address but its IPv6 traffic can't be managed, no rules were created: %w", contName, err)
		}
		states = append(states, &famState{fam: family6, addrs: addrs6})
		for netName, addr := range addrs6 {
			if _, ok := allNets[netName]; !ok {
				allNets[netName] = addr
			}
		}
	}

	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	// create chain for this container's rules
	contChainName := buildChainName(contName, container.ID)
	for _, st := range states {
		st.chain = &nftables.Chain{
			Name:  contChainName,
			Table: st.fam.table,
			Type:  nftables.ChainTypeFilter,
		}
		nfc.AddChain(st.chain)
	}
	if err := ignoringErr(nfc.Flush, syscall.EEXIST); err != nil {
		return fmt.Errorf("error creating chain: %w", err)
	}

	// add container IPs to jump set so traffic to/from this
	// container will go to the correct chain
	for _, st := range states {
		st.addrElems = make([]nftables.SetElement, 0, len(st.addrs))
		for _, addr := range st.addrs {
			st.addrElems = append(st.addrElems, nftables.SetElement{
				Key: addr,
				VerdictData: &expr.Verdict{
					Kind:  expr.VerdictJump,
					Chain: contChainName,
				},
			})
		}
		if err := nfc.SetAddElements(st.fam.addrSet, st.addrElems); err != nil {
			return fmt.Errorf("error marshaling set elements: %w", err)
		}
		if err := ignoringErr(nfc.Flush, syscall.EEXIST); err != nil {
			return fmt.Errorf("error adding elements to container address set: %w", err)
		}
	}

	// cleanup created rules if the context was canceled
	defer func() {
		if retErr == nil {
			return
		} else if !errors.Is(retErr, context.Canceled) {
			return
		}
		// if we are shutting down, don't delete rules
		select {
		case <-r.stopping:
			return
		default:
		}

		logger.Info("rule creation canceled, deleting created rules")
		for _, st := range states {
			if err := nfc.SetDeleteElements(st.fam.addrSet, st.addrElems); err != nil {
				logger.Error("error marshaling set elements", zap.Error(err))
			}
			if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
				logger.Error("error deleting elements to container address set", zap.Error(err))
			}
			for _, rule := range st.createdRules {
				if rule.Chain.Name == st.chain.Name && rule.Chain.Table.Family == st.chain.Table.Family {
					continue
				}
				if err := nfc.DelRule(rule); err != nil {
					logger.Error("error deleting rule", zap.Error(err))
					continue
				}
				if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
					logger.Error("error deleting rule", zap.Error(err))
				}
			}
			nfc.DelChain(st.chain)
			if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
				logger.Error("error deleting chain", zap.String("chain.name", st.chain.Name), zap.Error(err))
			}
			r.cleanupDomainState(nfc, logger, container.ID, st)
		}
	}()

	createRules := func(st *famState, rules []*nftables.Rule, insert bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		// keep track of rules that were generated from the given config
		// so we can remove rules in this container's chain not created
		// by whalewall
		st.createdRules = append(st.createdRules, rules...)

		// ensure we aren't creating existing rules
		currentRules := make(map[string][]*nftables.Rule)
		for _, rule := range rules {
			if _, ok := currentRules[rule.Chain.Name]; ok {
				continue
			}

			curRules, err := nfc.GetRules(rule.Table, rule.Chain)
			if err != nil {
				return fmt.Errorf("error getting rules of chain %q: %w", rule.Chain.Name, err)
			}
			currentRules[rule.Chain.Name] = curRules
		}

		j := 0
		for _, rule := range rules {
			// keep rules that don't already exist, discard the rest
			if findRule(logger, rule, currentRules[rule.Chain.Name]) {
				continue
			}
			rules[j] = rule
			j++
		}
		rules = rules[:j]

		if insert {
			// insert rules in reverse order that they were created in to maintain order
			for i := len(rules) - 1; i >= 0; i-- {
				nfc.InsertRule(rules[i])
			}
		} else {
			for _, rule := range rules {
				nfc.AddRule(rule)
			}
		}

		return nfc.Flush()
	}

	// create rule to drop all not explicitly allowed traffic
	for _, st := range states {
		err = createRules(st, []*nftables.Rule{createDropRule(st.chain, container.ID)}, false)
		if err != nil {
			return fmt.Errorf("error creating drop rule: %w", err)
		}
	}

	// add container to database
	tx, err := r.db.Begin(ctx, logger)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if isNew {
		if err := tx.AddContainer(ctx, container.ID, contName); err != nil {
			return fmt.Errorf("error adding container to database: %w", err)
		}
	}

	project := container.Config.Labels[composeProjectLabel]
	estContainers := make(map[string]struct{})
	if configExists {
		if err := r.populateOutputRules(ctx, tx, rulesCfg, container.ID, project, allNets, estContainers); err != nil {
			return fmt.Errorf("error validating rules: %w", err)
		}
	}

	service := container.Config.Labels[composeServiceLabel]
	for _, st := range states {
		stLogger := logger.With(zap.Stringer("family", st.fam))

		// create rules that allow traffic from another container to this
		// container if necessary that couldn't be created before
		stLogger.Debug("creating waiting rules")
		waitingRules, err := r.createWaitingContainerRules(ctx, nfc, stLogger, tx, container.ID, contName, service, project, st, estContainers)
		if err != nil {
			return fmt.Errorf("error creating waiting output rules: %w", err)
		}
		if err := createRules(st, waitingRules, true); err != nil {
			stLogger.Error("error creating waiting rules", zap.Error(err))
		}

		if st.fam.v6 {
			// IPv6 can't work without neighbor discovery
			if err := createRules(st, createICMPv6Rules(st.chain, container.ID), true); err != nil {
				stLogger.Error("error creating ICMPv6 rules", zap.Error(err))
			}
		}

		// if no rules were explicitly specified, only the rule that drops
		// traffic to/from the container will be added
		if !configExists {
			continue
		}

		// allow the container to reach the resolver if it has domain rules
		if r.dnsEnabled && hasDomainRules(rulesCfg) {
			dnsEPs := dnsEndpoints(st, container.NetworkSettings.Networks)
			if len(dnsEPs) == 0 {
				return fmt.Errorf("network gateway of container %q not found, can't redirect DNS queries", contName)
			}
			dnsRules, err := r.createDNSAccessRules(nfc, stLogger, container.ID, st, dnsEPs)
			if err != nil {
				return fmt.Errorf("error creating DNS rules: %w", err)
			}
			if err := createRules(st, dnsRules, true); err != nil {
				stLogger.Error("error creating DNS rules", zap.Error(err))
			}
		}

		// handle outbound rules
		stLogger.Debug("creating output rules")
		outputRules, err := r.createOutputRules(ctx, nfc, stLogger, tx, rulesCfg.Output, project, st, allNets, contName, container.ID)
		if err != nil {
			return fmt.Errorf("error creating output rules: %w", err)
		}
		if err := createRules(st, outputRules, true); err != nil {
			stLogger.Error("error creating output rules", zap.Error(err))
		}

		// handle port mapping rules, only IPv4 port mappings are
		// supported
		if st.fam.v6 {
			continue
		}
		stLogger.Debug("creating mapped port rules")
		portMapRules, err := r.createPortMappingRules(nfc, stLogger, container, contName, rulesCfg.MappedPorts, st.addrs, st.chain)
		if err != nil {
			return fmt.Errorf("error creating port mapping rules: %w", err)
		}
		if err := createRules(st, portMapRules, true); err != nil {
			stLogger.Error("error creating mapped port rules", zap.Error(err))
		}
	}

	if r.dnsEnabled && configExists && hasDomainRules(rulesCfg) {
		var endpoints []dnsEndpoint
		for _, st := range states {
			endpoints = append(endpoints, dnsEndpoints(st, container.NetworkSettings.Networks)...)
		}
		if err := r.registerDNS(nfc, logger, container.ID, contName, rulesCfg, states, endpoints); err != nil {
			return fmt.Errorf("error setting up DNS filtering: %w", err)
		}
	}

	// remove rules in this container's chain not created by whalewall
	for _, st := range states {
		currentRules, err := nfc.GetRules(st.chain.Table, st.chain)
		if err != nil {
			return fmt.Errorf("error getting rules of chain %q: %w", st.chain.Name, err)
		}
		createdContRules := make([]*nftables.Rule, 0, len(st.createdRules)/2)
		for _, rule := range st.createdRules {
			if rule.Chain.Name == st.chain.Name && rule.Chain.Table.Family == st.chain.Table.Family {
				createdContRules = append(createdContRules, rule)
			}
		}
		for _, currentRule := range currentRules {
			if !findRule(logger, currentRule, createdContRules) {
				if err := nfc.DelRule(currentRule); err != nil {
					logger.Error("error deleting rule", zap.Error(err))
					continue
				}
				logger.Warn("deleting rule not created by whalewall", zap.String("chain.name", st.chain.Name))
				if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
					logger.Error("error deleting rule", zap.Error(err))
				}
			}
		}
	}

	if !isNew {
		return nil
	}

	logger.Debug("adding to database")

	dbAddrs := make(map[string][]byte, len(addrs4)+len(addrs6))
	for netName, addr := range addrs4 {
		dbAddrs[netName+"|4"] = addr
	}
	for netName, addr := range addrs6 {
		dbAddrs[netName+"|6"] = addr
	}
	if err := r.addContainer(ctx, tx, container.ID, contName, service, dbAddrs, estContainers); err != nil {
		return fmt.Errorf("error adding container information to database: %w", err)
	}

	return nil
}

// createICMPv6Rules returns rules that allow the ICMPv6 messages IPv6
// can't function without: neighbor discovery (router and neighbor
// solicitation and advertisement, and redirect) and packet too big.
func createICMPv6Rules(chain *nftables.Chain, id string) []*nftables.Rule {
	newRule := func(exprs ...expr.Any) *nftables.Rule {
		base := []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			// [ payload load 1b @ transport header + 0 => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           1,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        0,
				DestRegister:  1,
			},
		}
		base = append(base, exprs...)
		base = append(base, &expr.Counter{}, acceptVerdict)
		return &nftables.Rule{
			Table:    chain.Table,
			Chain:    chain,
			Exprs:    base,
			UserData: []byte(id),
		}
	}

	return []*nftables.Rule{
		// neighbor discovery, types 133-137
		newRule(
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: []byte{133}},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: []byte{137}},
		),
		// packet too big
		newRule(&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}}),
	}
}

// stripName removes the leading "/" from a container name if necessary.
func stripName(name string) string {
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}
	return name
}

// populateOutputRules attempts to find the IPs of containers specified
// in output rules and fills the rules appropriately.
func (r *RuleManager) populateOutputRules(ctx context.Context, tx database.TX, cfg config, id, project string, addrs map[string][]byte, estConts map[string]struct{}) error {
	// only get a list of containers if at least one rule specifies a
	// container
	i := slices.IndexFunc(cfg.Output, func(r ruleConfig) bool {
		return r.Container != ""
	})
	if i == -1 {
		return nil
	}
	listedConts, err := r.dockerCli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return fmt.Errorf("error listing running containers: %w", err)
	}

	containers := make(map[string]types.ContainerJSON)
	for i, ruleCfg := range cfg.Output {
		// ensure the specified network exists
		if ruleCfg.Network != "" {
			if _, _, ok := findNetwork(ruleCfg.Network, project, addrs); !ok {
				return fmt.Errorf("output rule #%d: network %q not found",
					i,
					ruleCfg.Network,
				)
			}
		}

		if ruleCfg.Container != "" {
			// if the specified container is started, check that whalewall
			// is enabled for it and that it is a member of the specified
			// network
			var found bool
			for _, listedCont := range listedConts {
				if !containerNameMatches(ruleCfg.Container, listedCont.Labels, listedCont.Names...) {
					continue
				}

				// validate container settings
				cont, ok := containers[ruleCfg.Container]
				if !ok {
					cont, err = r.dockerCli.ContainerInspect(ctx, listedCont.ID)
					if err != nil {
						return fmt.Errorf("error inspecting container %s", listedCont.ID[:12])
					}
					enabled, err := whalewallEnabled(cont.Config.Labels)
					if err != nil {
						return fmt.Errorf("error parsing container %q label: %w", cont.ID[:12], err)
					}
					if !enabled {
						return fmt.Errorf("output rule #%d: container %q does not have whalewall enabled",
							i,
							ruleCfg.Container,
						)
					}
					containers[ruleCfg.Container] = cont
				}
				dstProject := cont.Config.Labels[composeProjectLabel]
				dstNetName, dstNetwork, ok := findNetwork(ruleCfg.Network, dstProject, cont.NetworkSettings.Networks)
				if !ok {
					return fmt.Errorf("output rule #%d: network %q not found for container %q",
						i,
						ruleCfg.Network,
						ruleCfg.Container,
					)
				}

				// if the container exists in the database it's been
				// processed already, and we can create rules involving
				// it now
				exists, err := r.containerExists(ctx, tx, cont.ID)
				if err != nil {
					return fmt.Errorf("error querying container %s from database: %w", cont.ID[:12], err)
				}
				if !exists {
					break
				}
				estConts[cont.ID] = struct{}{}
				found = true

				var contAddrs []netip.Addr
				for _, addrStr := range []string{dstNetwork.IPAddress, dstNetwork.GlobalIPv6Address} {
					if addrStr == "" {
						continue
					}
					addr, err := netip.ParseAddr(addrStr)
					if err != nil {
						return fmt.Errorf("error parsing IP of container %q from network %q: %w", ruleCfg.Container, dstNetName, err)
					}
					contAddrs = append(contAddrs, addr)
				}
				cfg.Output[i].contAddrs = contAddrs
				break
			}

			if !found {
				// we need to add rules to this container's chain, but it
				// hasn't been processed yet; wait until this container
				// is processed to create the rules
				cfg.Output[i].skip = true
			}
			// Add the rule to the database so when we are processing
			// this container, this rule will be created. This is done
			// even when the container has been processed so future
			// rule creation will be idempotent.
			var buf bytes.Buffer
			encoder := gob.NewEncoder(&buf)
			if err := encoder.Encode(ruleCfg); err != nil {
				return fmt.Errorf("error encoding waiting container rule: %w", err)
			}
			err := tx.AddWaitingContainerRule(ctx, database.AddWaitingContainerRuleParams{
				SrcContainerID:   id,
				DstContainerName: ruleCfg.Container,
				Rule:             buf.Bytes(),
			})
			if err != nil {
				return fmt.Errorf("error adding waiting container rule to database: %w", err)
			}
		}
	}

	return nil
}

// findNetwork attempts to find a given Docker network, returning the
// name the network was found by if possible. Docker Compose sometimes
// prepends the name of the Compose project to the name the user originally
// gave the network.
func findNetwork[T any](network, project string, addrs map[string]T) (string, T, bool) {
	var zero T
	netNames := [2]string{
		network,
		project + "_" + network,
	}
	for _, netName := range netNames {
		v, ok := addrs[netName]
		if ok {
			return netName, v, true
		}
	}

	return "", zero, false
}

// containerNameMatches returns true if a canonical container name can
// be found from a combination of labels and names.
func containerNameMatches(expectedName string, labels map[string]string, names ...string) bool {
	if len(expectedName) == 0 {
		return false
	}

	// maybe user prefixed a backslash already?
	if slices.Contains(names, expectedName) {
		return true
	}
	// docker prepends a backslash to container names
	slashPrefix := expectedName[0] == '/'
	if !slashPrefix && slices.Contains(names, "/"+expectedName) {
		return true
	}
	// if the user did prefix a slash, remove it here so we hopefully
	// get a match; the service name won't be prefixed with a backslash
	if slashPrefix {
		expectedName = expectedName[1:]
	}
	// check if the Docker Compose service name matches
	if serviceName, ok := labels[composeServiceLabel]; ok && serviceName == expectedName {
		return true
	}

	return false
}

func buildChainName(name, id string) string {
	return fmt.Sprintf("%s%s-%s", chainPrefix, name, id[:12])
}

// TODO: avoid creating almost duplicate rules as output rules
// createPortMappingRules adds nftables rules to allow or deny access to
// mapped ports.
func (r *RuleManager) createPortMappingRules(nfc firewallClient, logger *zap.Logger, container types.ContainerJSON, contName string, mappedPortsCfg mappedPorts, addrs map[string][]byte, chain *nftables.Chain) ([]*nftables.Rule, error) {
	// check if there are any mapped ports to create rules for
	var hasMappedPorts bool
	for _, hostPorts := range container.NetworkSettings.Ports {
		// if an image exposes a port but no mapped ports are configured,
		// the container port it will be here with no host ports
		if len(hostPorts) != 0 {
			hasMappedPorts = true
			break
		}
	}
	if (mappedPortsCfg.Localhost.Allow || mappedPortsCfg.External.Allow) && !hasMappedPorts {
		logger.Warn("local and/or external access to mapped ports is allowed, but there are not any mapped ports")
		return nil, nil
	}
	if !hasMappedPorts {
		return nil, nil
	}

	// prepend container name and ID to log prefixes
	if mappedPortsCfg.Localhost.LogPrefix != "" {
		mappedPortsCfg.Localhost.LogPrefix = formatLogPrefix(mappedPortsCfg.Localhost.LogPrefix, contName, container.ID)
	}
	if mappedPortsCfg.External.LogPrefix != "" {
		mappedPortsCfg.External.LogPrefix = formatLogPrefix(mappedPortsCfg.External.LogPrefix, contName, container.ID)
	}

	nftRules := make([]*nftables.Rule, 0, len(container.NetworkSettings.Networks))
	for netName, netSettings := range container.NetworkSettings.Networks {
		if _, ok := addrs[netName]; !ok {
			// the container has no IPv4 address on this network
			continue
		}
		gateway, err := netip.ParseAddr(netSettings.Gateway)
		if err != nil {
			return nil, fmt.Errorf("error parsing gateway of network: %w", err)
		}

		// sort mapped ports so rules are created deterministically making
		// testing much easier
		sortedPorts := maps.Keys(container.NetworkSettings.Ports)
		slices.Sort(sortedPorts)

		for _, port := range sortedPorts {
			hostPorts := container.NetworkSettings.Ports[port]
			localAllowed := mappedPortsCfg.Localhost.Allow

			var proto protocol
			if err := proto.UnmarshalText([]byte(port.Proto())); err != nil {
				return nil, fmt.Errorf("error parsing protocol: %w", err)
			}

			for _, hostPort := range hostPorts {
				addr, err := netip.ParseAddr(hostPort.HostIP)
				if err != nil {
					return nil, fmt.Errorf("error parsing IP of port mapping: %w", err)
				}
				// TODO: support IPv6
				if addr.Is6() {
					continue
				}

				// TODO: make same checks for external
				if localAllowed && !addr.IsUnspecified() && addr != localAddr {
					logger.Sugar().Warnf("local access to mapped ports is allowed, but port %s is listening on %s which is not accessible to localhost",
						hostPort.HostPort,
						addr,
					)
					continue
				}
				if !localAllowed && !addr.IsUnspecified() && addr != localAddr {
					// local access is not allowed, but localhost won't
					// be able to reach this port anyway since it isn't
					// listening on 0.0.0.0 or 127.0.0.1, so no need to
					// create any rules
					continue
				}

				if !localAllowed || (localAllowed && (!mappedPortsCfg.External.Allow || len(mappedPortsCfg.External.IPs) != 0)) {
					// Create rules to allow/drop traffic from container
					// network gateway to container; this will only be hit
					// for traffic originating from localhost after being
					// NATed by docker rules. If all external inbound
					// traffic is allowed, creating this is pointless as
					// the rule to allow all external inbound traffic will
					// cover traffic from the gateway too.
					rule := ruleDetails{
						inbound: true,
						addr:    addrs[netName],
						cfg: ruleConfig{
							LogPrefix: mappedPortsCfg.Localhost.LogPrefix,
							IPs: []addrOrRange{
								{addr: gateway},
							},
							Proto: proto,
							DstPorts: []rulePorts{
								{
									single: uint16(port.Int()),
								},
							},
							Verdict: mappedPortsCfg.Localhost.Verdict,
						},
						chain:  chain,
						contID: container.ID,
					}
					rule.cfg.Verdict.drop = !localAllowed

					rules, err := createNFTRules(nfc, logger, rule)
					if err != nil {
						return nil, fmt.Errorf("error creating firewall rules: %w", err)
					}
					nftRules = append(nftRules, rules...)
				}

				if !localAllowed {
					// Create rule to drop traffic going to the mapped
					// host port. This will prevent traffic originating
					// from localhost to be seen by Docker at all.
					hostPortInt, err := strconv.ParseUint(hostPort.HostPort, 10, 16)
					if err != nil {
						return nil, fmt.Errorf("error parsing host port of port mapping: %w", err)
					}

					localhostDropRule := ruleDetails{
						inbound: true,
						cfg: ruleConfig{
							IPs: []addrOrRange{
								{addr: localAddr},
							},
							Proto: proto,
							DstPorts: []rulePorts{
								{
									single: uint16(hostPortInt),
								},
							},
							Verdict: verdict{
								drop: true,
							},
						},
						chain:  whalewallChain,
						contID: container.ID,
					}

					rules, err := createNFTRules(nfc, logger, localhostDropRule)
					if err != nil {
						return nil, fmt.Errorf("error creating firewall rules: %w", err)
					}
					nftRules = append(nftRules, rules...)
				}
			}

			// if there are no host ports mapped to the container port,
			// don't create allow rules as the port wasn't exposed by
			// the user but rather was created from an EXPOSE Dockerfile
			// directive
			if mappedPortsCfg.External.Allow && len(hostPorts) > 0 {
				// only IPv4 mapped ports are supported
				externalIPs := family4.filterIPs(mappedPortsCfg.External.IPs)
				if len(mappedPortsCfg.External.IPs) != 0 && len(externalIPs) == 0 {
					continue
				}
				// create rules to allow external traffic to container
				rule := ruleDetails{
					inbound: true,
					addr:    addrs[netName],
					cfg: ruleConfig{
						LogPrefix: mappedPortsCfg.External.LogPrefix,
						IPs:       externalIPs,
						Proto:     proto,
						DstPorts: []rulePorts{
							{
								single: uint16(port.Int()),
							},
						},
						Verdict: mappedPortsCfg.External.Verdict,
					},
					chain:  chain,
					contID: container.ID,
				}

				rules, err := createNFTRules(nfc, logger, rule)
				if err != nil {
					return nil, fmt.Errorf("error creating firewall rules: %w", err)
				}
				nftRules = append(nftRules, rules...)
			}
		}
	}

	return nftRules, nil
}

// createOutputRules adds nftables rules to allow outbound access from
// a container.
func (r *RuleManager) createOutputRules(ctx context.Context, nfc firewallClient, logger *zap.Logger, tx database.TX, ruleCfgs []ruleConfig, project string, st *famState, allNets map[string][]byte, name, id string) ([]*nftables.Rule, error) {
	nftRules := make([]*nftables.Rule, 0, len(ruleCfgs)*3)
	for ruleIdx, ruleCfg := range ruleCfgs {
		// prepend container name and ID to log prefixes
		if ruleCfg.LogPrefix != "" {
			ruleCfg.LogPrefix = formatLogPrefix(ruleCfg.LogPrefix, name, id)
		}

		// only use the addresses that belong to this family; if a rule
		// only has addresses of the other family it doesn't apply here
		if len(ruleCfg.IPs) != 0 {
			ruleCfg.IPs = st.fam.filterIPs(ruleCfg.IPs)
			if len(ruleCfg.IPs) == 0 {
				continue
			}
		}

		rule := ruleDetails{
			inbound: false,
			cfg:     ruleCfg,
			chain:   st.chain,
			contID:  id,
		}

		if len(ruleCfg.Domains) != 0 {
			domainRules, err := r.createDomainRules(nfc, logger, st, ruleIdx, rule)
			if err != nil {
				return nil, err
			}
			nftRules = append(nftRules, domainRules...)
			continue
		}

		if ruleCfg.Network != "" {
			_, addr, ok := findNetwork(ruleCfg.Network, project, st.addrs)
			if !ok {
				if _, _, inOtherFamily := findNetwork(ruleCfg.Network, project, allNets); inOtherFamily {
					// the container is on this network but has no
					// address of this family
					continue
				}
				return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
			}
			rule.addr = addr

			if ruleCfg.Container != "" {
				if ruleCfg.skip {
					// the container either hasn't been started yet or
					// doesn't exist; this rule will be created when
					// processing this container later
					continue
				}

				var ips []addrOrRange
				for _, contAddr := range ruleCfg.contAddrs {
					if familyOfAddr(contAddr) == st.fam {
						ips = append(ips, addrOrRange{addr: contAddr})
					}
				}
				if len(ips) == 0 {
					// the destination container has no address of this
					// family
					continue
				}
				rule.cfg.IPs = ips

				dstID, dstName, err := r.getContainerIDAndName(ctx, tx, ruleCfg.Container)
				if err != nil {
					return nil, fmt.Errorf("error getting container %q ID from database: %w", ruleCfg.Container, err)
				}
				rule.estChain = &nftables.Chain{
					Table: st.fam.table,
					Name:  buildChainName(dstName, dstID),
				}
				rule.contID = dstID
				rule.estContID = id
			}

			rules, err := createNFTRules(nfc, logger, rule)
			if err != nil {
				return nil, fmt.Errorf("error creating firewall rules: %w", err)
			}
			nftRules = append(nftRules, rules...)
		} else {
			for _, addr := range st.addrs {
				rule.addr = addr
				rules, err := createNFTRules(nfc, logger, rule)
				if err != nil {
					return nil, fmt.Errorf("error creating firewall rules: %w", err)
				}
				nftRules = append(nftRules, rules...)
			}
		}
	}

	return nftRules, nil
}

// getContainerIDAndName returns the ID and canonical name of a container
// if it is present in the database.
func (r *RuleManager) getContainerIDAndName(ctx context.Context, db database.Querier, contName string) (string, string, error) {
	name := contName

	id, err := db.GetContainerID(ctx, contName)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("error getting container %q ID from database: %w", contName, err)
		}

		info, err := db.GetContainerIDAndNameFromAlias(ctx, contName)
		if err != nil {
			return "", "", fmt.Errorf("error getting container %q ID from database: %w", contName, err)
		}

		id = info.ID
		name = info.Name
	}

	return id, name, nil
}

// createWaitingContainerRules creates nftables rules to allow access
// from another container to this container. The other container was
// processed before this container, so rules concerning this container
// couldn't be created until now.
func (r *RuleManager) createWaitingContainerRules(ctx context.Context, nfc firewallClient, logger *zap.Logger, tx database.TX, id, name, service, project string, st *famState, estContainers map[string]struct{}) ([]*nftables.Rule, error) {
	addrs, chain := st.addrs, st.chain
	var (
		waitingRules []database.GetWaitingContainerRulesRow
		err          error
		aliases      = append([]string{name}, containerAliases(name, service)...)
	)

	for _, alias := range aliases {
		waitingRules, err = tx.GetWaitingContainerRules(ctx, alias)
		if err != nil {
			return nil, fmt.Errorf("error getting waiting container rules of %q from database: %w", alias, err)
		}

		if len(waitingRules) == 0 {
			continue
		}
		break
	}
	if waitingRules == nil {
		return nil, nil
	}

	nftRules := make([]*nftables.Rule, 0, len(waitingRules)*3)
	for _, waitingRule := range waitingRules {
		decoder := gob.NewDecoder(bytes.NewReader(waitingRule.Rule))
		var ruleCfg ruleConfig
		if err := decoder.Decode(&ruleCfg); err != nil {
			return nil, fmt.Errorf("error decoding waiting container rule: %w", err)
		}

		// find source container IP (not this container)
		srcCont, err := r.dockerCli.ContainerInspect(ctx, waitingRule.SrcContainerID)
		if err != nil {
			return nil, fmt.Errorf("error inspecting container %q: %w", waitingRule.Name, err)
		}
		srcProject := srcCont.Config.Labels[composeProjectLabel]
		srcNetName, srcNetwork, ok := findNetwork(ruleCfg.Network, srcProject, srcCont.NetworkSettings.Networks)
		if !ok {
			return nil, fmt.Errorf("network %q not found for container %q",
				ruleCfg.Network,
				ruleCfg.Container,
			)
		}
		srcAddrStr := srcNetwork.IPAddress
		if st.fam.v6 {
			srcAddrStr = srcNetwork.GlobalIPv6Address
		}
		if srcAddrStr == "" {
			// the source container has no address of this family
			continue
		}
		srcAddr, err := netip.ParseAddr(srcAddrStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing IP of container %q from network %q: %w", ruleCfg.Container, srcNetName, err)
		}

		// find destination container IP (this container)
		dstNetName, dstNetwork, ok := findNetwork(ruleCfg.Network, project, addrs)
		if !ok {
			if st.fam.v6 {
				continue
			}
			return nil, fmt.Errorf("network %q not found", ruleCfg.Network)
		}
		dstAddr, ok := netip.AddrFromSlice(dstNetwork)
		if !ok {
			return nil, fmt.Errorf("error parsing IP of from network %q", dstNetName)
		}
		ruleCfg.IPs = []addrOrRange{{addr: dstAddr}}

		// create rules
		rule := ruleDetails{
			inbound: false,
			addr:    addrBytes(srcAddr),
			cfg:     ruleCfg,
			chain: &nftables.Chain{
				Table: st.fam.table,
				Name:  buildChainName(waitingRule.Name, waitingRule.SrcContainerID),
			},
			estChain:  chain,
			contID:    id,
			estContID: waitingRule.SrcContainerID,
		}

		rules, err := createNFTRules(nfc, logger, rule)
		if err != nil {
			return nil, fmt.Errorf("error creating firewall rules: %w", err)
		}
		nftRules = append(nftRules, rules...)
		estContainers[waitingRule.SrcContainerID] = struct{}{}
	}

	return nftRules, nil
}

func formatLogPrefix(prefix, name, id string) string {
	prefix = fmt.Sprintf("whalewall-%s-%s %s", name, id[:12], prefix)
	if !strings.HasSuffix(prefix, ": ") {
		prefix += ": "
	}

	return prefix
}

type ruleDetails struct {
	inbound   bool
	addr      []byte
	cfg       ruleConfig
	chain     *nftables.Chain
	estChain  *nftables.Chain
	contID    string
	estContID string
	// domainSet is the set allowed destination addresses are looked up
	// in; it is used instead of the IPs of cfg for rules with domains
	domainSet *nftables.Set
}

func (r ruleDetails) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("inbound", r.inbound)
	if len(r.addr) != 0 {
		ip, ok := netip.AddrFromSlice(r.addr)
		if !ok {
			return fmt.Errorf("error parsing addr %v", r.addr)
		}
		enc.AddString("container_addr", ip.String())
	}
	zap.Inline(r.cfg).AddTo(enc)
	if r.chain != nil {
		enc.AddString("chain", r.chain.Name)
	}
	if r.estChain != nil {
		enc.AddString("est_chain", r.estChain.Name)
	}
	enc.AddString("cont_id", r.contID[:12])
	if r.estContID != "" {
		enc.AddString("est_cont_id", r.estContID[:12])
	}

	return nil
}

// createNFTRules returns a slice of [*nftables.Rule] described by rd.
func createNFTRules(nfc firewallClient, logger *zap.Logger, rd ruleDetails) ([]*nftables.Rule, error) {
	logger.Debug("generating rule", zap.Object("rule", rd))

	rules := make([]*nftables.Rule, 0, 3)
	estContID := rd.contID
	if rd.estChain == nil {
		rd.estChain = rd.chain
	} else {
		estContID = rd.estContID
	}

	// if the rule is a drop rule, only need to handle new traffic
	if rd.cfg.Verdict.drop {
		rule, err := createNFTRule(nfc, rd.inbound, false, stateNew, rd.addr, rd.cfg, 0, rd.chain, rd.contID, rd.domainSet)
		if err != nil {
			return nil, err
		}
		return append(rules, rule), nil
	}

	// rules that look up addresses in a set that is updated at runtime
	// need to be created like rules that log new traffic: only new
	// connections may be subject to the set, otherwise established
	// connections would be cut off when set elements expire
	separateNew := rd.cfg.LogPrefix != "" || rd.domainSet != nil

	if rd.cfg.Verdict.Queue == 0 {
		if !separateNew {
			newEstRule, err := createNFTRule(nfc, rd.inbound, false, stateNewEst, rd.addr, rd.cfg, 0, rd.chain, rd.contID, rd.domainSet)
			if err != nil {
				return nil, err
			}
			estRule, err := createNFTRule(nfc, !rd.inbound, true, stateEst, rd.addr, rd.cfg, 0, rd.estChain, estContID, rd.domainSet)
			if err != nil {
				return nil, err
			}
			return append(rules, newEstRule, estRule), nil
		}

		// create a separate rule for new traffic to log it
		dstNewRule, err := createNFTRule(nfc, rd.inbound, false, stateNew, rd.addr, rd.cfg, 0, rd.chain, rd.contID, rd.domainSet)
		if err != nil {
			return nil, err
		}
		dstEstRule, err := createNFTRule(nfc, rd.inbound, false, stateEst, rd.addr, rd.cfg, 0, rd.chain, rd.contID, rd.domainSet)
		if err != nil {
			return nil, err
		}
		srcEstRule, err := createNFTRule(nfc, !rd.inbound, true, stateEst, rd.addr, rd.cfg, 0, rd.estChain, estContID, rd.domainSet)
		if err != nil {
			return nil, err
		}
		return append(rules, dstNewRule, dstEstRule, srcEstRule), nil
	}

	// If there is no log prefix set we can create one inbound rule and
	// one outbound rule in some situations. Otherwise new traffic must
	// be logged.
	if !separateNew {
		if rd.inbound && rd.cfg.Verdict.Queue == rd.cfg.Verdict.InputEstQueue {
			// if rule is inbound and queue and established inbound queue
			// are the same, create one rule for inbound traffic
			newEstRule, err := createNFTRule(nfc, true, false, stateNewEst, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID, rd.domainSet)
			if err != nil {
				return nil, err
			}
			estRule, err := createNFTRule(nfc, false, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.estChain, estContID, rd.domainSet)
			if err != nil {
				return nil, err
			}
			return append(rules, newEstRule, estRule), nil
		} else if !rd.inbound && rd.cfg.Verdict.Queue == rd.cfg.Verdict.OutputEstQueue {
			// if rule is outbound and queue and established outbound queue
			// are the same, create one rule for outbound traffic
			newEstRule, err := createNFTRule(nfc, false, false, stateNewEst, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID, rd.domainSet)
			if err != nil {
				return nil, err
			}
			estRule, err := createNFTRule(nfc, true, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.estChain, estContID, rd.domainSet)
			if err != nil {
				return nil, err
			}
			return append(rules, newEstRule, estRule), nil
		}
	}

	// if rule is inbound and queue and established inbound queue
	// are different, need to create separate rules for them;
	// or, logging was requested which means we need to create a
	// separate rule for new traffic
	if rd.inbound {
		dstNewRule, err := createNFTRule(nfc, true, false, stateNew, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID, rd.domainSet)
		if err != nil {
			return nil, err
		}
		dstEstRule, err := createNFTRule(nfc, true, false, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.chain, rd.contID, rd.domainSet)
		if err != nil {
			return nil, err
		}
		srcEstRule, err := createNFTRule(nfc, false, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.estChain, estContID, rd.domainSet)
		if err != nil {
			return nil, err
		}
		return append(rules, dstNewRule, dstEstRule, srcEstRule), nil
	}

	// if rule is outbound and queue and established outbound queue
	// are different, need to create separate rules for them;
	// or, logging was requested which means we need to create a
	// separate rule for new traffic
	dstNewRule, err := createNFTRule(nfc, false, false, stateNew, rd.addr, rd.cfg, rd.cfg.Verdict.Queue, rd.chain, rd.contID, rd.domainSet)
	if err != nil {
		return nil, err
	}
	dstEstRule, err := createNFTRule(nfc, false, false, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.OutputEstQueue, rd.chain, rd.contID, rd.domainSet)
	if err != nil {
		return nil, err
	}
	srcEstRule, err := createNFTRule(nfc, true, true, stateEst, rd.addr, rd.cfg, rd.cfg.Verdict.InputEstQueue, rd.estChain, estContID, rd.domainSet)
	if err != nil {
		return nil, err
	}
	return append(rules, dstNewRule, dstEstRule, srcEstRule), nil
}

func createNFTRule(nfc firewallClient, inbound, inversePortOffsets bool, state uint32, addr []byte, cfg ruleConfig, queueNum uint16, chain *nftables.Chain, contID string, domainSet *nftables.Set) (*nftables.Rule, error) {
	fam := familyOfTable(chain.Table)
	addrOffset := fam.srcOffset
	cfgAddrOffset := fam.dstOffset
	if inbound {
		addrOffset = fam.dstOffset
		cfgAddrOffset = fam.srcOffset
	}
	proto := unix.IPPROTO_TCP
	if cfg.Proto == udp {
		proto = unix.IPPROTO_UDP
	}
	exprs := make([]expr.Any, 0, 15)
	if domainSet != nil {
		if len(addr) != 0 {
			exprs = append(exprs, matchAddrExprs(addr, addrOffset)...)
		}
		// only new connections have to match the set, established
		// connections were allowed when they were created
		if state&stateNew != 0 && !inversePortOffsets {
			exprs = append(exprs, getAddrExprN(cfgAddrOffset, fam.addrLen), matchFromNamedSetExpr(domainSet))
		}
	} else if len(cfg.IPs) != 0 {
		var addrExprs []expr.Any
		if len(addr) != 0 {
			addrExprs = matchAddrExprs(addr, addrOffset)
		}
		cfgAddrExprs, err := createIPExprs(nfc, cfg.IPs, cfgAddrOffset, chain)
		if err != nil {
			return nil, err
		}
		if inbound {
			exprs = append(exprs, cfgAddrExprs...)
			exprs = append(exprs, addrExprs...)
		} else {
			exprs = append(exprs, addrExprs...)
			exprs = append(exprs, cfgAddrExprs...)
		}
	} else if len(addr) != 0 {
		exprs = append(exprs, matchAddrExprs(addr, addrOffset)...)
	}

	if cfg.Proto != invalidProto {
		exprs = append(exprs, matchProtoExprs(proto)...)
	}

	var srcPortExprs []expr.Any
	var dstPortExprs []expr.Any
	if len(cfg.SrcPorts) != 0 {
		portOffset := srcPortOffset
		if inversePortOffsets {
			portOffset = dstPortOffset
		}
		portExprs, err := createPortExprs(nfc, cfg.SrcPorts, portOffset, chain)
		if err != nil {
			return nil, err
		}
		srcPortExprs = portExprs
	}
	if len(cfg.DstPorts) != 0 {
		portOffset := dstPortOffset
		if inversePortOffsets {
			portOffset = srcPortOffset
		}
		portExprs, err := createPortExprs(nfc, cfg.DstPorts, portOffset, chain)
		if err != nil {
			return nil, err
		}
		dstPortExprs = portExprs
	}
	if !inversePortOffsets {
		exprs = append(exprs, srcPortExprs...)
		exprs = append(exprs, dstPortExprs...)
	} else {
		exprs = append(exprs, dstPortExprs...)
		exprs = append(exprs, srcPortExprs...)
	}

	exprs = append(exprs, matchConnStateExprs(state)...)
	exprs = append(exprs, &expr.Counter{})
	if state == stateNew && cfg.LogPrefix != "" {
		exprs = append(exprs, logExpr(cfg.LogPrefix))
	}

	switch {
	case cfg.Verdict.Chain != "":
		exprs = append(exprs,
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: cfg.Verdict.Chain,
			},
		)
	case queueNum != 0:
		exprs = append(exprs,
			&expr.Queue{
				Num: queueNum,
			},
		)
	case cfg.Verdict.drop:
		exprs = append(exprs, dropVerdict)
	default:
		exprs = append(exprs, acceptVerdict)
	}

	return &nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		Exprs:    exprs,
		UserData: []byte(contID),
	}, nil
}

func createIPExprs(nfc firewallClient, addrs []addrOrRange, addrOffset uint32, chain *nftables.Chain) ([]expr.Any, error) {
	var exprs []expr.Any

	fam := familyOfTable(chain.Table)

	if len(addrs) == 1 {
		if addr, ok := addrs[0].Addr(); ok {
			exprs = matchAddrExprs(addrBytes(addr), addrOffset)
		} else if lowAddr, highAddr, ok := addrs[0].Range(); ok {
			exprs = matchAddrRangeExprs(lowAddr, highAddr, addrOffset)
		} else {
			// should never happen if cfg.IP.IsValid is true
			return nil, errors.New("whalewall bug: invalid IP address")
		}
		return exprs, nil
	}

	exprs = append(exprs, getAddrExprN(addrOffset, fam.addrLen))

	var singleAddr []byte
	var singleAddrElems []nftables.SetElement
	for _, addr := range addrs {
		if addr, ok := addr.Addr(); ok {
			singleAddr = addrBytes(addr)
			singleAddrElems = append(singleAddrElems, nftables.SetElement{
				Key: singleAddr,
			})
		}
	}
	if len(singleAddrElems) != 0 {
		if len(singleAddrElems) == 1 {
			// there is only one single addr, no need to create a set
			exprs = append(exprs, compareAddrExpr(singleAddr))
		} else {
			set := &nftables.Set{
				Table:     chain.Table,
				Anonymous: true,
				Constant:  true,
				KeyType:   nftables.TypeInetService,
			}
			if err := nfc.AddSet(set, singleAddrElems); err != nil {
				return nil, fmt.Errorf("error creating set: %w", err)
			}
			exprs = append(exprs, matchFromSetExpr(set))
		}
	}

	var addrRangeLow []byte
	var addrRangeHigh []byte
	var addrRangeElems []nftables.SetElement
	for _, addr := range addrs {
		if lowAddr, highAddr, ok := addr.Range(); ok {
			addrRangeLow = addrBytes(lowAddr)
			addrRangeHigh = addrBytes(highAddr)
			addrRangeElems = append(addrRangeElems, nftables.SetElement{
				Key: addrRangeLow,
			})
			addrRangeElems = append(addrRangeElems, nftables.SetElement{
				Key:         addrRangeHigh,
				IntervalEnd: true,
			})
		}
	}
	if len(addrRangeElems) != 0 {
		if len(addrRangeElems) == 2 {
			// there is only one single port range, no need to create a set
			exprs = append(exprs, compareAddrRangeExprs(addrRangeLow, addrRangeHigh)...)
		} else {
			set := &nftables.Set{
				Table:     chain.Table,
				Anonymous: true,
				Constant:  true,
				Interval:  true,
				KeyType:   nftables.TypeIPAddr,
			}
			if err := nfc.AddSet(set, addrRangeElems); err != nil {
				return nil, fmt.Errorf("error creating set: %w", err)
			}
			exprs = append(exprs, matchFromSetExpr(set))
		}
	}

	if len(exprs) == 1 {
		return nil, errors.New("whalewall bug: only one addr expr created")
	}

	return exprs, nil
}

func createPortExprs(nfc firewallClient, ports []rulePorts, portOffset uint32, chain *nftables.Chain) ([]expr.Any, error) {
	var exprs []expr.Any

	if len(ports) == 1 {
		if ports[0].single != 0 {
			exprs = matchPortExprs(ports[0].single, portOffset)
		} else {
			exprs = matchPortsExprs(ports[0].interval, portOffset)
		}
		return exprs, nil
	}

	exprs = append(exprs, getPortExpr(portOffset))

	var singlePort uint16
	var singlePortElems []nftables.SetElement
	for _, port := range ports {
		if port.single != 0 {
			singlePort = port.single
			singlePortElems = append(singlePortElems, nftables.SetElement{
				Key: binary.BigEndian.AppendUint16(nil, port.single),
			})
		}
	}
	if len(singlePortElems) != 0 {
		if len(singlePortElems) == 1 {
			// there is only one single port, no need to create a set
			exprs = append(exprs, comparePortExpr(singlePort))
		} else {
			set := &nftables.Set{
				Table:     chain.Table,
				Anonymous: true,
				Constant:  true,
				KeyType:   nftables.TypeInetService,
			}
			if err := nfc.AddSet(set, singlePortElems); err != nil {
				return nil, fmt.Errorf("error creating set: %w", err)
			}
			exprs = append(exprs, matchFromSetExpr(set))
		}
	}

	var portRange portInterval
	var portIntervalElems []nftables.SetElement
	for _, port := range ports {
		if port.single == 0 {
			portRange = port.interval
			portIntervalElems = append(portIntervalElems, nftables.SetElement{
				Key: binary.BigEndian.AppendUint16(nil, port.interval.min),
			})
			portIntervalElems = append(portIntervalElems, nftables.SetElement{
				Key:         binary.BigEndian.AppendUint16(nil, port.interval.max),
				IntervalEnd: true,
			})
		}
	}
	if len(portIntervalElems) != 0 {
		if len(portIntervalElems) == 2 {
			// there is only one single port range, no need to create a set
			exprs = append(exprs, comparePortsExprs(portRange)...)
		} else {
			set := &nftables.Set{
				Table:     chain.Table,
				Anonymous: true,
				Constant:  true,
				Interval:  true,
				KeyType:   nftables.TypeInetService,
			}
			if err := nfc.AddSet(set, portIntervalElems); err != nil {
				return nil, fmt.Errorf("error creating set: %w", err)
			}
			exprs = append(exprs, matchFromSetExpr(set))
		}
	}

	if len(exprs) == 1 {
		return nil, errors.New("whalewall bug: only one port expr created")
	}

	return exprs, nil
}

func matchAddrExprs(addr []byte, offset uint32) []expr.Any {
	return []expr.Any{
		getAddrExprN(offset, uint32(len(addr))),
		compareAddrExpr(addr),
	}
}

func getAddrExpr(offset uint32) expr.Any {
	return getAddrExprN(offset, 4)
}

func getAddrExprN(offset, size uint32) expr.Any {
	// [ payload load ...b @ network header + ... => reg 1 ]
	return &expr.Payload{
		OperationType: expr.PayloadLoad,
		Len:           size,
		Base:          expr.PayloadBaseNetworkHeader,
		Offset:        offset,
		DestRegister:  1,
	}
}

func compareAddrExpr(addr []byte) expr.Any {
	// [ cmp eq reg 1 ... ]
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     addr,
	}
}

func matchAddrRangeExprs(lowAddr, highAddr netip.Addr, offset uint32) []expr.Any {
	exprs := []expr.Any{getAddrExprN(offset, uint32(len(addrBytes(lowAddr))))}
	return append(exprs, compareAddrRangeExprs(addrBytes(lowAddr), addrBytes(highAddr))...)
}

func compareAddrRangeExprs(lowAddr, highAddr []byte) []expr.Any {
	return []expr.Any{
		// [ cmp gte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpGte,
			Register: 1,
			Data:     lowAddr,
		},
		// [ cmp lte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpLte,
			Register: 1,
			Data:     highAddr,
		},
	}
}

func matchProtoExprs(proto int) []expr.Any {
	return []expr.Any{
		// [ meta load l4proto => reg 1 ]
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		// [ cmp eq reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{byte(proto)},
		},
	}
}

func matchPortExprs(port uint16, offset uint32) []expr.Any {
	return []expr.Any{
		getPortExpr(offset),
		comparePortExpr(port),
	}
}

func getPortExpr(offset uint32) expr.Any {
	// [ payload load 2b @ transport header + ... => reg 1 ]
	return &expr.Payload{
		OperationType: expr.PayloadLoad,
		Len:           2,
		Base:          expr.PayloadBaseTransportHeader,
		Offset:        offset,
		DestRegister:  1,
	}
}

func comparePortExpr(port uint16) expr.Any {
	// [ cmp eq reg 1 ... ]
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binary.BigEndian.AppendUint16(nil, port),
	}
}

func matchPortsExprs(ports portInterval, offset uint32) []expr.Any {
	exprs := []expr.Any{getPortExpr(offset)}
	exprs = append(exprs, comparePortsExprs(ports)...)
	return exprs
}

func comparePortsExprs(ports portInterval) []expr.Any {
	return []expr.Any{
		// [ cmp gte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpGte,
			Register: 1,
			Data:     binary.BigEndian.AppendUint16(nil, ports.min),
		},
		// [ cmp lte reg 1 ... ]
		&expr.Cmp{
			Op:       expr.CmpOpLte,
			Register: 1,
			Data:     binary.BigEndian.AppendUint16(nil, ports.max),
		},
	}
}

// matchFromNamedSetExpr matches against a set that already exists in
// the kernel.
func matchFromNamedSetExpr(set *nftables.Set) expr.Any {
	// [ lookup reg 1 set ... 0x0 ]
	return &expr.Lookup{
		SourceRegister: 1,
		SetName:        set.Name,
	}
}

func matchFromSetExpr(set *nftables.Set) expr.Any {
	// [ lookup reg 1 set ... 0x0 ]
	return &expr.Lookup{
		SourceRegister: 1,
		SetID:          set.ID,
		SetName:        set.Name,
	}
}

func matchConnStateExprs(state uint32) []expr.Any {
	return []expr.Any{
		// [ ct load state => reg 1 ]
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		// [ bitwise reg 1 = ( reg 1 & ... ) ^ 0x00000000 ]
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binary.LittleEndian.AppendUint32(nil, state),
			Xor:            zeroUint32,
		},
		// [ cmp neq reg 1 0x00000000 ]
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     zeroUint32,
		},
	}
}

func logExpr(prefix string) expr.Any {
	return &expr.Log{
		Key:   (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_LEVEL),
		Level: expr.LogLevelInfo,
		Data:  []byte(prefix),
	}
}

func createDropRule(chain *nftables.Chain, id string) *nftables.Rule {
	return &nftables.Rule{
		Table: chain.Table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			logExpr(chain.Name + " drop: "),
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
		UserData: []byte(id),
	}
}

func ref[T any](v T) *T {
	return &v
}
