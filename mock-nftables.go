package whalewall

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mitchellh/copystructure"
	"go.uber.org/zap"
)

const anonSetName = "__set%d"

// setAllocNum is shared by all mock firewalls, which are used concurrently
var setAllocNum atomic.Uint32

type firewallClient interface {
	AddTable(t *nftables.Table) *nftables.Table
	DelTable(t *nftables.Table)

	AddChain(c *nftables.Chain) *nftables.Chain
	DelChain(c *nftables.Chain)
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)

	GetSets(t *nftables.Table) ([]*nftables.Set, error)
	AddSet(s *nftables.Set, vals []nftables.SetElement) error
	DelSet(s *nftables.Set)
	SetAddElements(s *nftables.Set, vals []nftables.SetElement) error
	SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error

	AddRule(r *nftables.Rule) *nftables.Rule
	DelRule(r *nftables.Rule) error
	InsertRule(r *nftables.Rule) *nftables.Rule
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)

	Flush() error
}

type mockFirewall struct {
	logger *zap.SugaredLogger

	changed bool

	tables map[string]*table
	chains map[string]chain

	unsetLookupExprs []*expr.Lookup

	flushErr error

	bf baseFirewallReaderWriter
}

type table struct {
	Sets setMap

	newAnonSets map[string]bool
}

type setMap map[string][]nftables.SetElement

type chain struct {
	Chain *nftables.Chain
	Rules []*nftables.Rule
}

type baseFirewallReaderWriter interface {
	readBaseFirewall(f func(base *mockFirewall))
	writeBaseFirewall(f func(base *mockFirewall))
}

type mockFirewallCreatorI interface {
	newMockFirewall() *mockFirewall
	baseFirewallReaderWriter
}

func newMockFirewallCreator(logger *zap.Logger) mockFirewallCreatorI {
	m := &mockFirewallCreator{
		baseFirewall: &mockFirewall{
			tables: make(map[string]*table),
			chains: make(map[string]chain),
		},
		logger: logger,
	}

	return m
}

type mockFirewallCreator struct {
	baseFirewall *mockFirewall
	mtx          sync.RWMutex
	logger       *zap.Logger
}

func (m *mockFirewallCreator) newMockFirewall() *mockFirewall {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	newFirewall := &mockFirewall{
		logger: m.logger.Sugar(),
		tables: clone(m.baseFirewall.tables),
		chains: clone(m.baseFirewall.chains),
		bf:     m,
	}
	initTables(newFirewall)

	return newFirewall
}

func initTables(m *mockFirewall) {
	for _, t := range m.tables {
		t.newAnonSets = make(map[string]bool)
	}
}

func (m *mockFirewallCreator) readBaseFirewall(f func(base *mockFirewall)) {
	m.mtx.RLock()
	f(m.baseFirewall)
	m.mtx.RUnlock()
}

func (m *mockFirewallCreator) writeBaseFirewall(f func(base *mockFirewall)) {
	m.mtx.Lock()
	f(m.baseFirewall)
	m.mtx.Unlock()
}

func (m *mockFirewall) AddTable(t *nftables.Table) *nftables.Table {
	m.changed = true

	if _, ok := m.tables[tkey(t)]; !ok {
		m.tables[tkey(t)] = &table{
			Sets:        make(setMap),
			newAnonSets: make(map[string]bool),
		}
	}

	return t
}

// tkey returns the key a table is stored under; IPv4 tables keep their
// name as key so tests can look them up by name.
func tkey(t *nftables.Table) string {
	if t != nil && t.Family == nftables.TableFamilyIPv6 {
		return "ip6:" + t.Name
	}
	return t.Name
}

func ckey(c *nftables.Chain) string {
	if c.Table != nil && c.Table.Family == nftables.TableFamilyIPv6 {
		return "ip6:" + c.Name
	}
	return c.Name
}

func ckeyIn(t *nftables.Table, c *nftables.Chain) string {
	if t != nil && t.Family == nftables.TableFamilyIPv6 {
		return "ip6:" + c.Name
	}
	return c.Name
}

func (m *mockFirewall) DelTable(t *nftables.Table) {
	m.changed = true

	if _, ok := m.tables[tkey(t)]; !ok {
		m.flushErr = syscall.ENOENT
		return
	}
	delete(m.tables, tkey(t))
	for key, c := range m.chains {
		if c.Chain.Table != nil && tkey(c.Chain.Table) == tkey(t) {
			delete(m.chains, key)
		}
	}
}

func (m *mockFirewall) GetSets(t *nftables.Table) ([]*nftables.Set, error) {
	var (
		sets []*nftables.Set
		err  error
	)
	m.bf.readBaseFirewall(func(base *mockFirewall) {
		bt, ok := base.tables[tkey(t)]
		if !ok {
			err = syscall.ENOENT
			return
		}
		for name := range bt.Sets {
			sets = append(sets, &nftables.Set{Table: t, Name: name})
		}
	})

	return sets, err
}

func (m *mockFirewall) AddChain(c *nftables.Chain) *nftables.Chain {
	m.changed = true

	if _, ok := m.chains[ckey(c)]; !ok {
		m.chains[ckey(c)] = chain{
			Chain: c,
		}
	}

	return c
}

func (m *mockFirewall) DelChain(c *nftables.Chain) {
	m.changed = true

	chain, ok := m.chains[ckey(c)]
	if !ok {
		m.logger.Errorf("chain %q not found", c.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	// delete rules so anonymous sets have a chance to get cleaned up
	for _, rule := range chain.Rules {
		m.delRule(rule, true)
	}

	delete(m.chains, ckey(c))
}

func (m *mockFirewall) ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error) {
	var chains []*nftables.Chain
	m.bf.readBaseFirewall(func(base *mockFirewall) {
		for _, c := range base.chains {
			if c.Chain.Table.Family == family {
				chains = append(chains, c.Chain)
			}
		}
	})

	return chains, nil
}

func (m *mockFirewall) AddSet(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[tkey(s.Table)]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	setName := s.Name
	if s.Anonymous {
		id := setAllocNum.Add(1)
		setName = fmt.Sprintf(anonSetName, id)
		s.ID = id
		s.Name = anonSetName

		t.newAnonSets[setName] = false
	}

	if _, ok := t.Sets[setName]; ok {
		// TODO: return error if set already exists?
		return nil
	}
	t.Sets[setName] = vals
	m.tables[tkey(s.Table)] = t

	return nil
}

func (m *mockFirewall) DelSet(s *nftables.Set) {
	m.changed = true

	t, ok := m.tables[tkey(s.Table)]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	delete(t.Sets, s.Name)
	m.tables[tkey(s.Table)] = t
}

func (m *mockFirewall) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[tkey(s.Table)]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.Sets[s.Name]
	if !ok {
		m.logger.Errorf("set %q not found", s.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	// don't add elements already present in set
	for _, val := range vals {
		if !slices.ContainsFunc(elements, func(e nftables.SetElement) bool {
			if !bytes.Equal(e.Key, val.Key) {
				return false
			}
			if !bytes.Equal(e.Val, val.Val) {
				return false
			}
			if !bytes.Equal(e.KeyEnd, val.KeyEnd) {
				return false
			}
			if e.IntervalEnd != val.IntervalEnd {
				return false
			}
			if (e.VerdictData != nil) != (val.VerdictData != nil) {
				return false
			}
			if e.VerdictData != nil {
				if e.VerdictData.Kind != val.VerdictData.Kind {
					return false
				}
				if e.VerdictData.Chain != val.VerdictData.Chain {
					return false
				}
			}
			if e.Timeout != val.Timeout {
				return false
			}
			return true
		}) {
			elements = append(elements, val)
		}
	}

	t.Sets[s.Name] = elements
	m.tables[tkey(s.Table)] = t

	return nil
}

func (m *mockFirewall) SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[tkey(s.Table)]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.Sets[s.Name]
	if !ok {
		m.logger.Errorf("set %q not found", s.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	for _, v := range vals {
		i := slices.IndexFunc(elements, func(e nftables.SetElement) bool {
			if !bytes.Equal(e.Key, v.Key) {
				return false
			}
			if !bytes.Equal(e.KeyEnd, v.KeyEnd) {
				return false
			}
			if !bytes.Equal(e.Val, v.Val) {
				return false
			}
			return e.IntervalEnd == v.IntervalEnd
		})
		if i == -1 {
			m.logger.Errorf("set element with key %v not found", v.Key)
			m.flushErr = syscall.ENOENT
			continue
		}
		elements = slices.Delete(elements, i, i+1)
	}
	t.Sets[s.Name] = elements
	m.tables[tkey(s.Table)] = t

	return nil
}

func (m *mockFirewall) AddRule(r *nftables.Rule) *nftables.Rule {
	m.changed = true

	t, ok := m.tables[tkey(r.Table)]
	if !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return r
	}
	c, ok := m.chains[ckey(r.Chain)]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	// copy this rule so if we update it after flush the caller's rule
	// won't be updated
	rCopy := clone(r)
	m.checkRule(rCopy, t)

	c.Rules = append(c.Rules, rCopy)
	m.chains[ckey(r.Chain)] = c

	return r
}

func (m *mockFirewall) DelRule(r *nftables.Rule) error {
	m.changed = true

	m.delRule(r, false)

	return nil
}

func (m *mockFirewall) delRule(r *nftables.Rule, softDel bool) {
	if _, ok := m.tables[tkey(r.Table)]; !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return
	}
	c, ok := m.chains[ckey(r.Chain)]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	i := slices.IndexFunc(c.Rules, func(r2 *nftables.Rule) bool {
		return rulesEqual(m.logger.Desugar(), r, r2)
	})
	if i == -1 {
		m.logger.Error("rule not found")
		m.flushErr = syscall.ENOENT
		return
	}

	// delete any anonymous sets associated with this rule
	for _, ruleExpr := range c.Rules[i].Exprs {
		lookupExpr, ok := ruleExpr.(*expr.Lookup)
		if !ok || !strings.HasPrefix(lookupExpr.SetName, "__set") {
			continue
		}

		m.DelSet(&nftables.Set{
			Table: c.Rules[i].Table,
			Name:  lookupExpr.SetName,
		})
	}

	if !softDel {
		c.Rules = slices.Delete(c.Rules, i, i+1)
		m.chains[ckey(r.Chain)] = c
	}
}

func (m *mockFirewall) InsertRule(r *nftables.Rule) *nftables.Rule {
	m.changed = true

	t, ok := m.tables[tkey(r.Table)]
	if !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return r
	}
	c, ok := m.chains[ckey(r.Chain)]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	// copy this rule so if we update it after flush the caller's rule
	// won't be updated
	rCopy := clone(r)
	m.checkRule(rCopy, t)

	c.Rules = slices.Insert(c.Rules, 0, rCopy)
	m.chains[ckey(r.Chain)] = c

	return r
}

func (m *mockFirewall) checkRule(r *nftables.Rule, t *table) {
	for _, ruleExpr := range r.Exprs {
		lookup, ok := ruleExpr.(*expr.Lookup)
		if ok && lookup.SetName == anonSetName {
			if lookup.SetID == 0 {
				m.flushErr = syscall.EINVAL
				break
			}
			// mark this expression to be updated after flush
			m.unsetLookupExprs = append(m.unsetLookupExprs, lookup)

			setName := fmt.Sprintf(anonSetName, lookup.SetID)
			if _, ok := t.newAnonSets[setName]; ok {
				// mark this anonymous set as valid now that a rule has
				// been added that uses it
				t.newAnonSets[setName] = true
			}
		}
	}
}

func (m *mockFirewall) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	var rules []*nftables.Rule
	var err error
	m.bf.readBaseFirewall(func(base *mockFirewall) {
		ch, ok := base.chains[ckeyIn(t, c)]
		if !ok {
			err = syscall.ENOENT
			return
		}
		rules = clone(ch.Rules)
	})

	return rules, err
}

func (m *mockFirewall) Flush() error {
	defer func() {
		m.changed = false
		m.bf.readBaseFirewall(func(base *mockFirewall) {
			m.tables = clone(base.tables)
			initTables(m)
			m.chains = clone(base.chains)
		})
		m.flushErr = nil
	}()

	if m.flushErr != nil {
		return m.flushErr
	}

	// update lookup expressions
	for _, lookupExpr := range m.unsetLookupExprs {
		lookupExpr.SetName = fmt.Sprintf(lookupExpr.SetName, lookupExpr.SetID)
		lookupExpr.SetID = 0
	}
	m.unsetLookupExprs = nil

	// delete unused anonymous sets
	for _, t := range m.tables {
		for newAnonSet, used := range t.newAnonSets {
			if !used {
				delete(t.Sets, newAnonSet)
			}
		}
	}

	// only propagate changes if there were changes made
	if m.changed {
		m.bf.writeBaseFirewall(func(base *mockFirewall) {
			base.tables = m.tables
			base.chains = m.chains
		})
	}

	return nil
}

func clone[T any](t T) T {
	//nolint: forcetypeassert
	return copystructure.Must(copystructure.Copy(t)).(T)
}
