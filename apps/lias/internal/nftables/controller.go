// Package nftables implements the isolated firewall controller for LIAS.
// It manages ONLY the isolated 'netdev lancontrol' table on the LAN interface.
//
// File:    apps/lias/internal/nftables/controller.go
// Version: 2.0 (GAP-1 / GAP-04 Resolved: Added mandatory Device hook binding)
package nftables

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/user/lias-dis/apps/lias/internal/config"
)

// Controller manages the netdev lancontrol table, chain, sets, and rules.
type Controller struct {
	mu    sync.Mutex
	conn  *nftables.Conn
	cfg   config.NftablesConfig
	table *nftables.Table
	chain *nftables.Chain
	sets  map[string]*nftables.Set
}

// NewController initializes a new nftables controller instance.
func NewController(cfg config.NftablesConfig) *Controller {
	return &Controller{
		cfg:  cfg,
		sets: make(map[string]*nftables.Set),
	}
}

// Init creates or flushes the lancontrol table, ingress chain, sets, and filtering rules.
func (c *Controller) Init() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to netlink nftables: %w", err)
	}
	c.conn = conn

	// 1. Create or bind the netdev table
	c.table = c.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyNetdev,
		Name:   c.cfg.TableName,
	})

	// 2. Create the ingress chain with HIGHEST priority (-500) bound to the physical network interface
	// Priority -500 ensures lancontrol executes BEFORE sing-box (-150) and inet filter (0).
	// Crucial GAP-1 / GAP-04 Fix: Explicit Device string field MUST be set so google/nftables
	// emits NFTA_HOOK_DEV, attaching this chain to eth0's RX path in the kernel driver.
	c.chain = c.conn.AddChain(&nftables.Chain{
		Name:     "ingress",
		Table:    c.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookIngress,
		Priority: nftables.ChainPriorityRef(-500),
		Device:   c.cfg.Interface, // <-- MANDATORY KERNEL HOOK INTERFACE BINDING
	})

	// Flush existing chain rules to prevent duplicate rule accumulation
	c.conn.FlushChain(c.chain)

	// 3. Create sets for allowed and blocked elements
	timeout := 1 * time.Hour

	allowedIPsSet := &nftables.Set{
		Name:    "allowed_ips",
		Table:   c.table,
		KeyType: nftables.TypeIPAddr,
		Timeout: timeout,
	}
	if err := c.conn.AddSet(allowedIPsSet, nil); err != nil {
		return fmt.Errorf("failed to create allowed_ips set: %w", err)
	}
	c.sets["allowed_ips"] = allowedIPsSet

	allowedMACsSet := &nftables.Set{
		Name:    "allowed_macs",
		Table:   c.table,
		KeyType: nftables.TypeEtherAddr,
		Timeout: timeout,
	}
	if err := c.conn.AddSet(allowedMACsSet, nil); err != nil {
		return fmt.Errorf("failed to create allowed_macs set: %w", err)
	}
	c.sets["allowed_macs"] = allowedMACsSet

	blockedIPsSet := &nftables.Set{
		Name:    "blocked_ips",
		Table:   c.table,
		KeyType: nftables.TypeIPAddr,
		Timeout: timeout,
	}
	if err := c.conn.AddSet(blockedIPsSet, nil); err != nil {
		return fmt.Errorf("failed to create blocked_ips set: %w", err)
	}
	c.sets["blocked_ips"] = blockedIPsSet

	blockedMACsSet := &nftables.Set{
		Name:    "blocked_macs",
		Table:   c.table,
		KeyType: nftables.TypeEtherAddr,
		Timeout: timeout,
	}
	if err := c.conn.AddSet(blockedMACsSet, nil); err != nil {
		return fmt.Errorf("failed to create blocked_macs set: %w", err)
	}
	c.sets["blocked_macs"] = blockedMACsSet

	// Interface match bytes (null-terminated interface string for iifname "eth0" matching)
	ifaceBytes := []byte(c.cfg.Interface + "\x00")

	// 4. DROP RULES FIRST (Highest Precedence)
	// Rule 1: BLOCK MACs on c.cfg.Interface (iifname "eth0" @blocked_macs drop)
	c.conn.AddRule(&nftables.Rule{
		Table: c.table,
		Chain: c.chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseLLHeader,
				Offset:        6, // Source MAC starts at byte 6 in Ethernet header
				Len:           6,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        "blocked_macs",
				SetID:          c.sets["blocked_macs"].ID,
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Rule 2: BLOCK IPs on c.cfg.Interface (iifname "eth0" @blocked_ips drop)
	c.conn.AddRule(&nftables.Rule{
		Table: c.table,
		Chain: c.chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        12, // Source IPv4 starts at byte 12
				Len:           4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        "blocked_ips",
				SetID:          c.sets["blocked_ips"].ID,
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Rule 3: ALLOW MACs on c.cfg.Interface (iifname "eth0" @allowed_macs accept)
	c.conn.AddRule(&nftables.Rule{
		Table: c.table,
		Chain: c.chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseLLHeader,
				Offset:        6,
				Len:           6,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        "allowed_macs",
				SetID:          c.sets["allowed_macs"].ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Rule 4: ALLOW IPs on c.cfg.Interface (iifname "eth0" @allowed_ips accept)
	c.conn.AddRule(&nftables.Rule{
		Table: c.table,
		Chain: c.chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        12,
				Len:           4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        "allowed_ips",
				SetID:          c.sets["allowed_ips"].ID,
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	if err := c.conn.Flush(); err != nil {
		return fmt.Errorf("failed to initialize netdev lancontrol table: %w", err)
	}

	slog.Info("nftables netdev table initialized successfully with priority -500 and drop-first rules",
		"table", c.cfg.TableName, "iface", c.cfg.Interface)
	return nil
}

// FlushTable completely removes the lancontrol table from the system kernel.
func (c *Controller) FlushTable() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || c.table == nil {
		return nil
	}

	c.conn.FlushTable(c.table)
	c.conn.DelTable(c.table)

	if err := c.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush netdev table: %w", err)
	}

	slog.Info("nftables netdev lancontrol table flushed and removed", "table", c.cfg.TableName)
	return nil
}

// SetElements structure for transferring IP and MAC element sets.
type SetElements struct {
	IPs  []net.IP
	MACs []net.HardwareAddr
}

// Apply flushes existing sets and atomically updates netfilter sets with new elements.
func (c *Controller) Apply(allowed, blocked SetElements) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("nftables connection uninitialized")
	}

	c.conn.FlushSet(c.sets["allowed_ips"])
	c.conn.FlushSet(c.sets["allowed_macs"])
	c.conn.FlushSet(c.sets["blocked_ips"])
	c.conn.FlushSet(c.sets["blocked_macs"])

	if err := c.addElements("allowed_ips", allowed.IPs); err != nil {
		return err
	}
	if err := c.addElements("allowed_macs", allowed.MACs); err != nil {
		return err
	}
	if err := c.addElements("blocked_ips", blocked.IPs); err != nil {
		return err
	}
	if err := c.addElements("blocked_macs", blocked.MACs); err != nil {
		return err
	}

	if err := c.conn.Flush(); err != nil {
		return fmt.Errorf("failed to commit nftables set update: %w", err)
	}

	return nil
}

func (c *Controller) addElements(setName string, items interface{}) error {
	set := c.sets[setName]
	var elements []nftables.SetElement

	switch v := items.(type) {
	case []net.IP:
		for _, ip := range v {
			if ip4 := ip.To4(); ip4 != nil {
				elements = append(elements, nftables.SetElement{Key: ip4})
			}
		}
	case []net.HardwareAddr:
		for _, mac := range v {
			if len(mac) == 6 {
				elements = append(elements, nftables.SetElement{Key: mac})
			}
		}
	default:
		return fmt.Errorf("unsupported element type for set %s", setName)
	}

	if len(elements) > 0 {
		if err := c.conn.SetAddElements(set, elements); err != nil {
			return fmt.Errorf("failed to add elements to set %s: %w", setName, err)
		}
	}
	return nil
}
