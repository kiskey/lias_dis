// Package nftables implements the isolated firewall controller for LIAS.
// It manages ONLY the isolated 'netdev lancontrol' table on the LAN interface.
//
// File:    apps/lias/internal/nftables/controller.go
// Version: 2.4 (Critical fixes: Zero timeout, IPv6 support, Safe reinitializeConn)
package nftables

import (
    "fmt"
    "log/slog"
    "net"
    "sync"

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
    c.chain = c.conn.AddChain(&nftables.Chain{
        Name:     "ingress",
        Table:    c.table,
        Type:     nftables.ChainTypeFilter,
        Hooknum:  nftables.ChainHookIngress,
        Priority: nftables.ChainPriorityRef(-500),
        Device:   c.cfg.Interface,
    })

    // Flush existing chain rules to prevent duplicate rule accumulation
    c.conn.FlushChain(c.chain)

    // 3. Create sets for allowed and blocked elements
    // LIAS-NFT-02 Fix: Removed Timeout to prevent silent unblocking of dormant devices.
    
    allowedIPsSet := &nftables.Set{
        Name:    "allowed_ips",
        Table:   c.table,
        KeyType: nftables.TypeIPAddr,
    }
    if err := c.conn.AddSet(allowedIPsSet, nil); err != nil {
        return fmt.Errorf("failed to create allowed_ips set: %w", err)
    }
    c.sets["allowed_ips"] = allowedIPsSet

    allowedMACsSet := &nftables.Set{
        Name:    "allowed_macs",
        Table:   c.table,
        KeyType: nftables.TypeEtherAddr,
    }
    if err := c.conn.AddSet(allowedMACsSet, nil); err != nil {
        return fmt.Errorf("failed to create allowed_macs set: %w", err)
    }
    c.sets["allowed_macs"] = allowedMACsSet

    blockedIPsSet := &nftables.Set{
        Name:    "blocked_ips",
        Table:   c.table,
        KeyType: nftables.TypeIPAddr,
    }
    if err := c.conn.AddSet(blockedIPsSet, nil); err != nil {
        return fmt.Errorf("failed to create blocked_ips set: %w", err)
    }
    c.sets["blocked_ips"] = blockedIPsSet

    blockedMACsSet := &nftables.Set{
        Name:    "blocked_macs",
        Table:   c.table,
        KeyType: nftables.TypeEtherAddr,
    }
    if err := c.conn.AddSet(blockedMACsSet, nil); err != nil {
        return fmt.Errorf("failed to create blocked_macs set: %w", err)
    }
    c.sets["blocked_macs"] = blockedMACsSet

    // LIAS-NFT-01 Fix: Add IPv6 Sets
    allowedIPs6Set := &nftables.Set{
        Name:    "allowed_ips_v6",
        Table:   c.table,
        KeyType: nftables.TypeIP6Addr,
    }
    if err := c.conn.AddSet(allowedIPs6Set, nil); err != nil {
        return fmt.Errorf("failed to create allowed_ips_v6 set: %w", err)
    }
    c.sets["allowed_ips_v6"] = allowedIPs6Set

    blockedIPs6Set := &nftables.Set{
        Name:    "blocked_ips_v6",
        Table:   c.table,
        KeyType: nftables.TypeIP6Addr,
    }
    if err := c.conn.AddSet(blockedIPs6Set, nil); err != nil {
        return fmt.Errorf("failed to create blocked_ips_v6 set: %w", err)
    }
    c.sets["blocked_ips_v6"] = blockedIPs6Set

    // Interface match bytes (null-terminated interface string for iifname "eth0" matching)
    ifaceBytes := []byte(c.cfg.Interface + "\x00")

    // 4. DROP RULES FIRST (Highest Precedence for MACs)
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
                SetName:        "blocked_macs",
                SetID:          c.sets["blocked_macs"].ID,
            },
            &expr.Verdict{Kind: expr.VerdictDrop},
        },
    })

    // Rule 2: ALLOW MACs on c.cfg.Interface
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

    // Rule 3: BLOCK IPv4s on c.cfg.Interface
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
                SetName:        "blocked_ips",
                SetID:          c.sets["blocked_ips"].ID,
            },
            &expr.Verdict{Kind: expr.VerdictDrop},
        },
    })

    // Rule 4: ALLOW IPv4s on c.cfg.Interface
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

    // LIAS-NFT-01 Fix: Rule 5: BLOCK IPv6s
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
                Offset:        8,  // IPv6 Src IP starts at byte 8
                Len:           16, // 128 bits
            },
            &expr.Lookup{
                SourceRegister: 1,
                SetName:        "blocked_ips_v6",
                SetID:          c.sets["blocked_ips_v6"].ID,
            },
            &expr.Verdict{Kind: expr.VerdictDrop},
        },
    })

    // LIAS-NFT-01 Fix: Rule 6: ALLOW IPv6s
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
                Offset:        8,
                Len:           16,
            },
            &expr.Lookup{
                SourceRegister: 1,
                SetName:        "allowed_ips_v6",
                SetID:          c.sets["allowed_ips_v6"].ID,
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
    IPs    []net.IP
    MACs   []net.HardwareAddr
    IPsV6  []net.IP // NEW: IPv6 support
}

// Apply flushes existing sets and atomically updates netfilter sets with new elements.
// Note: Batching is handled by the netlink connection internally.
func (c *Controller) Apply(allowed, blocked SetElements) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.conn == nil {
        return fmt.Errorf("nftables connection uninitialized")
    }

    // 1. Pre-validate and prepare all elements
    allowedIPEls := make([]nftables.SetElement, 0, len(allowed.IPs))
    for _, ip := range allowed.IPs {
        if ip4 := ip.To4(); ip4 != nil {
            allowedIPEls = append(allowedIPEls, nftables.SetElement{Key: ip4})
        }
    }

    allowedMACEls := make([]nftables.SetElement, 0, len(allowed.MACs))
    for _, mac := range allowed.MACs {
        if len(mac) == 6 {
            allowedMACEls = append(allowedMACEls, nftables.SetElement{Key: mac})
        }
    }

    blockedIPEls := make([]nftables.SetElement, 0, len(blocked.IPs))
    for _, ip := range blocked.IPs {
        if ip4 := ip.To4(); ip4 != nil {
            blockedIPEls = append(blockedIPEls, nftables.SetElement{Key: ip4})
        }
    }

    blockedMACEls := make([]nftables.SetElement, 0, len(blocked.MACs))
    for _, mac := range blocked.MACs {
        if len(mac) == 6 {
            blockedMACEls = append(blockedMACEls, nftables.SetElement{Key: mac})
        }
    }

    // IPv6 Elements
    allowedIP6Els := make([]nftables.SetElement, 0, len(allowed.IPsV6))
    for _, ip := range allowed.IPsV6 {
        if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil {
            allowedIP6Els = append(allowedIP6Els, nftables.SetElement{Key: ip6})
        }
    }

    blockedIP6Els := make([]nftables.SetElement, 0, len(blocked.IPsV6))
    for _, ip := range blocked.IPsV6 {
        if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil {
            blockedIP6Els = append(blockedIP6Els, nftables.SetElement{Key: ip6})
        }
    }

    // 2. Queue flush operations
    c.conn.FlushSet(c.sets["allowed_ips"])
    c.conn.FlushSet(c.sets["allowed_macs"])
    c.conn.FlushSet(c.sets["blocked_ips"])
    c.conn.FlushSet(c.sets["blocked_macs"])
    c.conn.FlushSet(c.sets["allowed_ips_v6"])
    c.conn.FlushSet(c.sets["blocked_ips_v6"])

    // 3. Queue add operations, handling errors to reset buffer if needed
    if len(allowedIPEls) > 0 {
        if err := c.conn.SetAddElements(c.sets["allowed_ips"], allowedIPEls); err != nil {
            c.reinitializeConn()
            return fmt.Errorf("failed to queue allowed_ips: %w", err)
        }
    }
    if len(allowedMACEls) > 0 {
        if err := c.conn.SetAddElements(c.sets["allowed_macs"], allowedMACEls); err != nil {
            c.reinitializeConn()
            return fmt.Errorf("failed to queue allowed_macs: %w", err)
        }
    }
    if len(blockedIPEls) > 0 {
        if err := c.conn.SetAddElements(c.sets["blocked_ips"], blockedIPEls); err != nil {
            c.reinitializeConn()
            return fmt.Errorf("failed to queue blocked_ips: %w", err)
        }
    }
    if len(blockedMACEls) > 0 {
        if err := c.conn.SetAddElements(c.sets["blocked_macs"], blockedMACEls); err != nil {
            c.reinitializeConn()
            return fmt.Errorf("failed to queue blocked_macs: %w", err)
        }
    }
    if len(allowedIP6Els) > 0 {
        if err := c.conn.SetAddElements(c.sets["allowed_ips_v6"], allowedIP6Els); err != nil {
            c.reinitializeConn()
            return fmt.Errorf("failed to queue allowed_ips_v6: %w", err)
        }
    }
    if len(blockedIP6Els) > 0 {
        if err := c.conn.SetAddElements(c.sets["blocked_ips_v6"], blockedIP6Els); err != nil {
            c.reinitializeConn()
            return fmt.Errorf("failed to queue blocked_ips_v6: %w", err)
        }
    }

    // 4. Commit transaction atomically
    if err := c.conn.Flush(); err != nil {
        c.reinitializeConn()
        return fmt.Errorf("failed to commit nftables set update: %w", err)
    }

    return nil
}

// reinitializeConn safely discards the dirty netlink buffer by creating a new connection
// and completely rebuilding the kernel state references.
// LIAS-NFT-09 Fix: Call Init() to repopulate c.table, c.chain, and c.sets safely.
func (c *Controller) reinitializeConn() {
    slog.Warn("Reinitializing nftables connection due to transaction failure")
    conn, err := nftables.New()
    if err != nil {
        slog.Error("Failed to reinitialize nftables connection", "error", err)
        return
    }
    c.conn = conn
    
    // Re-run Init to safely re-create or bind to the existing table/chain/sets.
    // We must unlock temporarily because Init expects the lock.
    c.mu.Unlock()
    if err := c.Init(); err != nil {
        slog.Error("Failed to safely rebuild nftables state after connection reset", "error", err)
    }
    c.mu.Lock()
}
