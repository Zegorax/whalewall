package whalewall

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
)

const (
	filterTableName      = "filter"
	dockerChainName      = "DOCKER-USER"
	inputChainName       = "INPUT"
	outputChainName      = "OUTPUT"
	whalewallChainName   = "whalewall"
	containerAddrSetName = "whalewall-container-addrs"
)

var (
	filterTable = &nftables.Table{
		Name:   filterTableName,
		Family: nftables.TableFamilyIPv4,
	}
	whalewallChain = &nftables.Chain{
		Name:  whalewallChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	}
	containerAddrSet = &nftables.Set{
		Table:    filterTable,
		Name:     containerAddrSetName,
		IsMap:    true,
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeVerdict,
	}
)

// errNoDockerChain is returned if Docker hasn't created its chains for
// a family, which is the case for IPv6 when Docker's ip6tables support
// is disabled.
var errNoDockerChain = errors.New("couldn't find required Docker chain, is Docker running?")

// createBaseRules creates the rules and sets all container chains
// depend on for the given family.
func (r *RuleManager) createBaseRules() error {
	return r.createFamilyBaseRules(family4)
}

func (r *RuleManager) createFamilyBaseRules(fam *family) error {
	filterTable, whalewallChain := fam.table, fam.whalewallChain
	srcJumpRule, dstJumpRule := fam.jumpRule(true), fam.jumpRule(false)

	nfc, err := r.newFirewallClient()
	if err != nil {
		return fmt.Errorf("error creating netlink connection: %w", err)
	}

	chains, err := nfc.ListChainsOfTableFamily(filterTable.Family)
	if err != nil {
		return fmt.Errorf("error listing %s chains: %w", fam, err)
	}
	var (
		whalewallChainFound bool
		dockerChain         *nftables.Chain
		inputChain          *nftables.Chain
		outputChain         *nftables.Chain
	)
	for _, c := range chains {
		if c.Table.Name != filterTableName {
			continue
		}

		switch c.Name {
		case dockerChainName:
			dockerChain = c
		case whalewallChainName:
			whalewallChainFound = true
		case inputChainName:
			inputChain = c
		case outputChainName:
			outputChain = c
		}
	}
	if dockerChain == nil {
		return errNoDockerChain
	}

	// get or create whalewall chain
	var mainChainRules []*nftables.Rule
	var addContainerJumpRules bool
	if !whalewallChainFound {
		nfc.AddChain(whalewallChain)
		addContainerJumpRules = true
	} else {
		mainChainRules, err = nfc.GetRules(filterTable, whalewallChain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %w", whalewallChainName, err)
		}
		if len(mainChainRules) == 0 {
			addContainerJumpRules = true
		}
	}

	// add rule to jump from DOCKER-USER chain to whalewall chain
	dockerRules, err := nfc.GetRules(filterTable, dockerChain)
	if err != nil {
		return fmt.Errorf("error listing rules of %q chain: %w", dockerChainName, err)
	}
	dockerUserJumpRule := createJumpRule(dockerChain, whalewallChainName)
	if !findRule(r.logger, dockerUserJumpRule, dockerRules) {
		nfc.InsertRule(dockerUserJumpRule)
	}

	// add rule to jump from INPUT/OUTPUT chains to whalewall chain
	handleMainChain := func(name string, hook *nftables.ChainHook, mainChain *nftables.Chain) error {
		if mainChain == nil {
			r.logger.Debug("creating chain", zap.String("chain.name", name))
			// INPUT and OUTPUT sometimes don't exist in nftables
			mainChain = &nftables.Chain{
				Name:     name,
				Table:    filterTable,
				Hooknum:  hook,
				Priority: nftables.ChainPriorityFilter,
				Type:     nftables.ChainTypeFilter,
				Policy:   ref(nftables.ChainPolicyAccept),
			}
			nfc.AddChain(mainChain)
			if err := ignoringErr(nfc.Flush, syscall.EEXIST); err != nil {
				return fmt.Errorf("error creating chain: %w", err)
			}
		}

		rules, err := nfc.GetRules(filterTable, mainChain)
		if err != nil {
			return fmt.Errorf("error listing rules of %q chain: %w", name, err)
		}
		jumpRule := createJumpRule(mainChain, whalewallChainName)
		if !findRule(r.logger, jumpRule, rules) {
			nfc.InsertRule(jumpRule)
		}

		return nil
	}
	if err := handleMainChain(inputChainName, nftables.ChainHookInput, inputChain); err != nil {
		return err
	}
	if err := handleMainChain(outputChainName, nftables.ChainHookOutput, outputChain); err != nil {
		return err
	}

	// create a map that maps container IPs to their respective chain
	if err := nfc.AddSet(fam.addrSet, nil); err != nil {
		return fmt.Errorf("error adding set %q: %w", containerAddrSetName, err)
	}

	// create rules to jump to container chain if packet is from/to a container
	if addContainerJumpRules || !findRule(r.logger, srcJumpRule, mainChainRules) {
		nfc.AddRule(srcJumpRule)
	}

	if addContainerJumpRules || !findRule(r.logger, dstJumpRule, mainChainRules) {
		nfc.AddRule(dstJumpRule)
	}

	if err := nfc.Flush(); err != nil {
		return fmt.Errorf("error flushing nftables commands: %w", err)
	}

	return nil
}

func createJumpRule(srcChain *nftables.Chain, dstChainName string) *nftables.Rule {
	return &nftables.Rule{
		Table: srcChain.Table,
		Chain: srcChain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: dstChainName,
			},
		},
	}
}
