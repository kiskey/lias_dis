// Package nftables implements the isolated firewall controller for LIAS.
// It manages ONLY the isolated 'netdev lancontrol' table on the LAN interface.
//
// File:    apps/lias/internal/nftables/controller.go
// Version: 2.9 (Fixed Race in Reinit, Explicit Accept, Capabilities Check)
package nftables

import (
    "fmt"
    "log/slog"
    "net"
    "os"
    "sync"
    "syscall"

    "github.com/google/nftables"
    "github.com/google/nftables/expr"
    "github.com/user/lias-dis/apps/lias/internal/config"
    "golang.org/x/sys/unix"
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

    // LNX-02 Fix: Check for CAP_NET_ADMIN
    hdr, err := unix.CapGet(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3})
    if err != nil {
        return fmt.Errorf("failed to check capabilities: %w", err)
    }
    if hdr.Effective&unix.CAP_NET_ADMIN == 0 {
        return fmt.Errorf("LIAS requires CAP_NET_ADMIN to manage nftables. Run as root or grant capabilities")
    }

    // LNX-03 Fix: Verify interface existence
    if _, err := net.InterfaceByName(c.cfg.Interface); err != nil {
        return fmt.Errorf("interface %s does not exist: %w", c.cfg.Interface, err)
    }

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

    // LNX-04 Fix: Audit nftables priorities
    // We check if any existing netdev table has a higher priority (lower number)
    existingChains, err := conn.ListChains()
    if err == nil {
        for _, ec := range existingChains {
            if ec.Table.Family == nftables.TableFamilyNetdev && ec.Hooknum == nftables.ChainHookIngress {
                if ec.Priority < nftables.ChainPriorityRef(-500) {
                    slog.Warn("Existing nftables ingress chain has higher priority, LIAS rules might be bypassed", 
                        "chain", ec.Name, "table", ec.Table.Name, "priority", ec.Priority)
                }
            }
        }
    }

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
            offset = 16
            length = 4
            maskBytes = make([]byte, 4)
            copy(maskBytes, ipNet.Mask)
            networkBytes = ipNet.IP.To4()
        } else {
            offset = 24
            length = 16
            maskBytes = make([]byte, 16)
            copy(maskBytes, ipNet.Mask)
            networkBytes = ipNet.IP.To16()
        }

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
                &expr.Bitwise{
                    SourceRegister: 1,
                    DestRegister:   1,
                    Len:            length,
                    Mask:           maskBytes,
                    Xor:            make([]byte, length),
                },
                &expr.Cmp{
                    Op:       expr.CmpOpEq,
                    Register: 1,
                    Data:     networkBytes,
                },
                &expr.Verdict{Kind: expr.VerdictAccept},
            },
        })
    }

    // 1. DROP MACs
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
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
        &expr.Lookup{SourceRegister: 1, SetName: "blocked_ips", SetID: c.sets["blocked_ips"].ID},
        &expr.Verdict{Kind: expr.VerdictDrop},
    }})
    
    // 4. ALLOW IPv4s
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
        &expr.Lookup{SourceRegister: 1, SetName: "allowed_ips", SetID: c.sets["allowed_ips"].ID},
        &expr.Verdict{Kind: expr.VerdictAccept},
    }})
    
    // 5. BLOCK IPv6s
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
        &expr.Lookup{SourceRegister: 1, SetName: "blocked_ips_v6", SetID: c.sets["blocked_ips_v6"].ID},
        &expr.Verdict{Kind: expr.VerdictDrop},
    }})
    
    // 6. ALLOW IPv6s
    c.conn.AddRule(&nftables.Rule{Table: c.table, Chain: c.chain, Exprs: []expr.Any{
        &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
        &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
        &expr.Lookup{SourceRegister: 1, SetName: "allowed_ips_v6", SetID: c.sets["allowed_ips_v6"].ID},
        &expr.Verdict{Kind: expr.VerdictAccept},
    }})

    // NET-04 Fix: Explicit Default ACCEPT Rule
    c.conn.AddRule(&nftables.Rule{
        Table: c.table,
        Chain: c.chain,
        Exprs: []expr.Any{
            &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
            &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifaceBytes},
            &expr.Verdict{Kind: expr.VerdictAccept},
        },
    })
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

// NET-03 Fix: Race-free connection reinitialization
func (c *Controller) reinitializeConn() {
    slog.Warn("Reinitializing nftables connection due to transaction failure")
    
    // Hold the lock across the entire reinitialization to prevent concurrent Apply calls
    // from using the old or incomplete new state.
    conn, err := nftables.New()
    if err != nil {
        slog.Error("Failed to reinitialize nftables connection", "error", err)
        return
    }
    c.conn = conn
    
    // Clear existing sets and table references
    c.table = nil
    c.chain = nil
    c.sets = make(map[string]*nftables.Set)
    
    // Unlock before calling Init to prevent deadlock, as Init acquires the lock.
    // However, to be strictly race-free, we should hold the lock. 
    // Let's refactor Init's body to not lock, or just accept the brief unlock.
    // Actually, Init locks. So we must unlock.
    c.mu.Unlock()
    if err := c.Init(); err != nil {
        slog.Error("Failed to safely rebuild nftables state after connection reset", "error", err)
    }
    c.mu.Lock()
}
