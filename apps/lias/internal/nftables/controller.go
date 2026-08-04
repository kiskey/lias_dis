// Package nftables implements the isolated firewall controller for LIAS.
// It manages ONLY the isolated 'netdev lancontrol' table on the LAN interface.
//
// File:    apps/lias/internal/nftables/controller.go
// Version: 2.7 (Corrected LAN bypass destination IP offsets and bitwise CIDR matching)
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

type Controller struct {
    mu    sync.Mutex
    conn  *nftables.Conn
    cfg   config.NftablesConfig
    table *nftables.Table
    chain *nftables.Chain
    sets  map[string]*nftables.Set
}

func NewController(cfg config.NftablesConfig) *Controller {
    return &Controller{
        cfg:  cfg,
        sets: make(map[string]*nftables.Set),
    }
}

func (c *Controller) Init() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    conn, err := nftables.New()
    if err != nil {
        return fmt.Errorf("failed to connect to netlink nftables: %w", err)
    }
    c.conn = conn

    c.table = c.conn.AddTable(&nftables.Table{
        Family: nftables.TableFamilyNetdev,
        Name:   c.cfg.TableName,
    })

    c.chain = c.conn.AddChain(&nftables.Chain{
        Name:     "ingress",
        Table:    c.table,
        Type:     nftables.ChainTypeFilter,
        Hooknum:  nftables.ChainHookIngress,
        Priority: nftables.ChainPriorityRef(-500),
        Device:   c.cfg.Interface,
    })

    c.conn.FlushChain(c.chain)

    allowedIPsSet := &nftables.Set{
        Name:    "allowed_ips",
        Table:   c.table,
        KeyType: nftables.TypeIPAddr,
    }
    c.conn.AddSet(allowedIPsSet, nil)
    c.sets["allowed_ips"] = allowedIPsSet

    allowedMACsSet := &nftables.Set{
        Name:    "allowed_macs",
        Table:   c.table,
        KeyType: nftables.TypeEtherAddr,
    }
    c.conn.AddSet(allowedMACsSet, nil)
    c.sets["allowed_macs"] = allowedMACsSet

    blockedIPsSet := &nftables.Set{
        Name:    "blocked_ips",
        Table:   c.table,
        KeyType: nftables.TypeIPAddr,
    }
    c.conn.AddSet(blockedIPsSet, nil)
    c.sets["blocked_ips"] = blockedIPsSet

    blockedMACsSet := &nftables.Set{
        Name:    "blocked_macs",
        Table:   c.table,
        KeyType: nftables.TypeEtherAddr,
    }
    c.conn.AddSet(blockedMACsSet, nil)
    c.sets["blocked_macs"] = blockedMACsSet

    allowedIPs6Set := &nftables.Set{
        Name:    "allowed_ips_v6",
        Table:   c.table,
        KeyType: nftables.TypeIP6Addr,
    }
    c.conn.AddSet(allowedIPs6Set, nil)
    c.sets["allowed_ips_v6"] = allowedIPs6Set

    blockedIPs6Set := &nftables.Set{
        Name:    "blocked_ips_v6",
        Table:   c.table,
        KeyType: nftables.TypeIP6Addr,
    }
    c.conn.AddSet(blockedIPs6Set, nil)
    c.sets["blocked_ips_v6"] = blockedIPs6Set

    ifaceBytes := []byte(c.cfg.Interface + "\x00")

    // Build and inject rules
    c.addRules(ifaceBytes)

    if err := c.conn.Flush(); err != nil {
        return fmt.Errorf("failed to initialize netdev lancontrol table: %w", err)
    }

    slog.Info("nftables netdev table initialized successfully with priority -500, drop-first rules, and LAN bypass",
        "table", c.cfg.TableName, "iface", c.cfg.Interface, "bypass_subnets", len(c.cfg.LanSubnets))
    return nil
}

func (c *Controller) addRules(ifaceBytes []byte) {
    // 0. LAN BYPASS RULES (Highest Priority)
    // Allows blocked devices to communicate with local infrastructure (printers, NAS, DNS)
    for _, subnetStr := range c.cfg.LanSubnets {
        _, ipNet, err := net.ParseCIDR(subnetStr)
        if err != nil {
            slog.Warn("Invalid LAN subnet in config, skipping bypass rule", "subnet", subnetStr)
            continue
        }

        isV4 := ipNet.IP.To4() != nil
        var offset uint32
        var length uint32
        var maskBytes []byte
        var networkBytes []byte

        if isV4 {
            offset = 16 // IPv4 Destination IP offset (bytes)
            length = 4  // IPv4 length
            maskBytes = make([]byte, 4)
            copy(maskBytes, ipNet.Mask)
            networkBytes = ipNet.IP.To4()
        } else {
            offset = 24 // IPv6 Destination IP offset (bytes)
            length = 16 // IPv6 length
            maskBytes = make([]byte, 16)
            copy(maskBytes, ipNet.Mask)
            networkBytes = ipNet.IP.To16()
        }

        // Must match iifname AND destination subnet
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
                    Offset:        offset,
                    Len:           length,
                },
                // Bitwise AND the destination IP with the subnet mask
                &expr.Bitwise{
                    SourceRegister: 1,
                    DestRegister:   1,
                    Len:            length,
                    Mask:           maskBytes,
                    Xor:            []byte{},
                },
                // Compare the masked result to the network base address
                &expr.Cmp{
                    Op:       expr.CmpOpEq,
                    Register: 1,
                    Data:     networkBytes,
                },
                &expr.Verdict{Kind: expr.VerdictAccept},
            },
        })
    }

    // 1. DROP MACs (Applies only to Internet-bound traffic)
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
        &expr.Lookup{SourceRegister: 1, SetName: "blocked_macs", SetID: c.sets["blocked_macs"].ID},
        &expr.Verdict{Kind: expr.VerdictDrop},
    }})
    
    // 2. ALLOW MACs
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
        &expr.Lookup{SourceRegister: 1, SetName: "allowed_macs", SetID: c.sets["allowed_macs"].ID},
        &expr.Verdict{Kind: expr.VerdictAccept},
    }})
    
    // 3. BLOCK IPv4s
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // Src IP
        &expr.Lookup{SourceRegister: 1, SetName: "blocked_ips", SetID: c.sets["blocked_ips"].ID},
        &expr.Verdict{Kind: expr.VerdictDrop},
    }})
    
    // 4. ALLOW IPv4s
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, // Src IP
        &expr.Lookup{SourceRegister: 1, SetName: "allowed_ips", SetID: c.sets["allowed_ips"].ID},
        &expr.Verdict{Kind: expr.VerdictAccept},
    }})
    
    // 5. BLOCK IPv6s
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, // Src IP
        &expr.Lookup{SourceRegister: 1, SetName: "blocked_ips_v6", SetID: c.sets["blocked_ips_v6"].ID},
        &expr.Verdict{Kind: expr.VerdictDrop},
    }})
    
    // 6. ALLOW IPv6s
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, // Src IP
        &expr.Lookup{SourceRegister: 1, SetName: "allowed_ips_v6", SetID: c.sets["allowed_ips_v6"].ID},
        &expr.Verdict{Kind: expr.VerdictAccept},
    }})
}

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

// SetDiff represents the exact elements to add and remove from the kernel sets.
type SetDiff struct {
    AllowedIPsToAdd   []net.IP
    AllowedIPsToRem   []net.IP
    BlockedIPsToAdd   []net.IP
    BlockedIPsToRem   []net.IP
    AllowedMACsToAdd  []net.HardwareAddr
    AllowedMACsToRem  []net.HardwareAddr
    BlockedMACsToAdd  []net.HardwareAddr
    BlockedMACsToRem  []net.HardwareAddr
    AllowedIP6sToAdd  []net.IP
    AllowedIP6sToRem  []net.IP
    BlockedIP6sToAdd  []net.IP
    BlockedIP6sToRem  []net.IP
}

func (c *Controller) Apply(diff SetDiff) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.conn == nil {
        return fmt.Errorf("nftables connection uninitialized")
    }

    c.queueElements("allowed_ips", diff.AllowedIPsToAdd, diff.AllowedIPsToRem, false)
    c.queueElements("allowed_macs", diff.AllowedMACsToAdd, diff.AllowedMACsToRem, true)
    c.queueElements("blocked_ips", diff.BlockedIPsToAdd, diff.BlockedIPsToRem, false)
    c.queueElements("blocked_macs", diff.BlockedMACsToAdd, diff.BlockedMACsToRem, true)
    c.queueElements("allowed_ips_v6", diff.AllowedIP6sToAdd, diff.AllowedIP6sToRem, false)
    c.queueElements("blocked_ips_v6", diff.BlockedIP6sToAdd, diff.BlockedIP6sToRem, false)

    if err := c.conn.Flush(); err != nil {
        c.reinitializeConn()
        return fmt.Errorf("failed to commit nftables set diff: %w", err)
    }

    return nil
}

func (c *Controller) queueElements(setName string, toAdd, toRem interface{}, isMAC bool) {
    set := c.sets[setName]
    if set == nil {
        return
    }

    if isMAC {
        addEls := make([]nftables.SetElement, 0, len(toAdd.([]net.HardwareAddr)))
        for _, mac := range toAdd.([]net.HardwareAddr) {
            if len(mac) == 6 {
                addEls = append(addEls, nftables.SetElement{Key: mac})
            }
        }
        if len(addEls) > 0 {
            c.conn.SetAddElements(set, addEls)
        }

        remEls := make([]nftables.SetElement, 0, len(toRem.([]net.HardwareAddr)))
        for _, mac := range toRem.([]net.HardwareAddr) {
            if len(mac) == 6 {
                remEls = append(remEls, nftables.SetElement{Key: mac})
            }
        }
        if len(remEls) > 0 {
            c.conn.SetDeleteElements(set, remEls)
        }
    } else {
        addEls := make([]nftables.SetElement, 0, len(toAdd.([]net.IP)))
        for _, ip := range toAdd.([]net.IP) {
            if ip4 := ip.To4(); ip4 != nil && setName != "allowed_ips_v6" && setName != "blocked_ips_v6" {
                addEls = append(addEls, nftables.SetElement{Key: ip4})
            } else if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil && (setName == "allowed_ips_v6" || setName == "blocked_ips_v6") {
                addEls = append(addEls, nftables.SetElement{Key: ip6})
            }
        }
        if len(addEls) > 0 {
            c.conn.SetAddElements(set, addEls)
        }

        remEls := make([]nftables.SetElement, 0, len(toRem.([]net.IP)))
        for _, ip := range toRem.([]net.IP) {
            if ip4 := ip.To4(); ip4 != nil && setName != "allowed_ips_v6" && setName != "blocked_ips_v6" {
                remEls = append(remEls, nftables.SetElement{Key: ip4})
            } else if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil && (setName == "allowed_ips_v6" || setName == "blocked_ips_v6") {
                remEls = append(remEls, nftables.SetElement{Key: ip6})
            }
        }
        if len(remEls) > 0 {
            c.conn.SetDeleteElements(set, remEls)
        }
    }
}

func (c *Controller) reinitializeConn() {
    slog.Warn("Reinitializing nftables connection due to transaction failure")
    conn, err := nftables.New()
    if err != nil {
        slog.Error("Failed to reinitialize nftables connection", "error", err)
        return
    }
    c.conn = conn
    
    c.mu.Unlock()
    if err := c.Init(); err != nil {
        slog.Error("Failed to safely rebuild nftables state after connection reset", "error", err)
    }
    c.mu.Lock()
}
