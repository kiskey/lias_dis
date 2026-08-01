// Package nftables implements the isolated firewall controller for LIAS.
// It creates and manages ONLY the 'netdev lancontrol' table.
//
// File:    apps/lias/internal/nftables/controller.go
// Version: 1.1
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
    "golang.org/x/sys/unix"
)

// Controller manages the nftables table, chain, and sets.
type Controller struct {
    mu    sync.Mutex
    conn  *nftables.Conn
    cfg   config.NftablesConfig
    table *nftables.Table
    chain *nftables.Chain
    sets  map[string]*nftables.Set
}

// NewController initializes a new nftables controller.
func NewController(cfg config.NftablesConfig) *Controller {
    return &Controller{
        conn: nftables.New(),
        cfg:  cfg,
        sets: make(map[string]*nftables.Set),
    }
}

// Init creates or flushes the lancontrol table, chain, and sets.
func (c *Controller) Init() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    // 1. Create or get the netdev table
    c.table = c.conn.AddTable(&nftables.Table{
        Family: nftables.TableFamilyNetdev,
        Name:   c.cfg.TableName,
    })

    // 2. Create or flush the ingress chain
    c.chain = c.conn.AddChain(&nftables.Chain{
        Name:     "ingress",
        Table:    c.table,
        Type:     nftables.ChainTypeFilter,
        Hooknum:  nftables.ChainHookIngress,
        Priority: nftables.ChainPriorityRef(0),
        Device:   c.cfg.Interface,
    })

    // 3. Create the four sets with timeout flags
    // 1 hour timeout in milliseconds (3600 * 1000)
    timeout := time.Hour

    c.sets["allowed_ips"] = c.conn.AddSet(&nftables.Set{
        Name:    "allowed_ips",
        Table:   c.table,
        KeyType: nftables.TypeIPAddr,
        Timeout: &timeout,
    }, nil)

    c.sets["allowed_macs"] = c.conn.AddSet(&nftables.Set{
        Name:    "allowed_macs",
        Table:   c.table,
        KeyType: nftables.TypeEtherAddr,
        Timeout: &timeout,
    }, nil)

    c.sets["blocked_ips"] = c.conn.AddSet(&nftables.Set{
        Name:    "blocked_ips",
        Table:   c.table,
        KeyType: nftables.TypeIPAddr,
        Timeout: &timeout,
    }, nil)

    c.sets["blocked_macs"] = c.conn.AddSet(&nftables.Set{
        Name:    "blocked_macs",
        Table:   c.table,
        KeyType: nftables.TypeEtherAddr,
        Timeout: &timeout,
    }, nil)

    // 4. Create the rules using real nftables expressions
    // Rule: Allow MACs
    c.conn.AddRule(&nftables.Rule{
        Table: c.table,
        Chain: c.chain,
        Exprs: []expr.Any{
            // Load MAC source address (Offset 8, Len 6) into register 1
            &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 8, Len: 6},
            // Lookup register 1 in allowed_macs set
            &expr.Lookup{SourceRegister: 1, SetName: "allowed_macs", SetID: c.sets["allowed_macs"].ID},
            // If matched, Accept
            &expr.Verdict{Kind: expr.VerdictAccept},
        },
    })

    // Rule: Allow IPs
    c.conn.AddRule(&nftables.Rule{
        Table: c.table,
        Chain: c.chain,
        Exprs: []expr.Any{
            // Load IP source address (Offset 12, Len 4) into register 1
            &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
            // Lookup register 1 in allowed_ips set
            &expr.Lookup{SourceRegister: 1, SetName: "allowed_ips", SetID: c.sets["allowed_ips"].ID},
            // If matched, Accept
            &expr.Verdict{Kind: expr.VerdictAccept},
        },
    })

    // Rule: Block MACs
    c.conn.AddRule(&nftables.Rule{
        Table: c.table,
        Chain: c.chain,
        Exprs: []expr.Any{
            &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 8, Len: 6},
            &expr.Lookup{SourceRegister: 1, SetName: "blocked_macs", SetID: c.sets["blocked_macs"].ID},
            &expr.Verdict{Kind: expr.VerdictDrop},
        },
    })

    // Rule: Block IPs
    c.conn.AddRule(&nftables.Rule{
        Table: c.table,
        Chain: c.chain,
        Exprs: []expr.Any{
            &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
            &expr.Lookup{SourceRegister: 1, SetName: "blocked_ips", SetID: c.sets["blocked_ips"].ID},
            &expr.Verdict{Kind: expr.VerdictDrop},
        },
    })

    if err := c.conn.Flush(); err != nil {
        return fmt.Errorf("failed to initialize nftables: %w", err)
    }

    slog.Info("nftables initialized", "table", c.cfg.TableName, "interface", c.cfg.Interface)
    return nil
}

// FlushTable removes the entire lancontrol table from the system.
func (c *Controller) FlushTable() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.conn.FlushTable(c.table)
    c.conn.DelTable(c.table)

    if err := c.conn.Flush(); err != nil {
        return fmt.Errorf("failed to flush nftables table: %w", err)
    }

    slog.Info("nftables table flushed and removed", "table", c.cfg.TableName)
    return nil
}

// SetElements provides a safe way to pass elements to the Builder.
type SetElements struct {
    IPs  []net.IP
    MACs []net.HardwareAddr
}

// Apply updates the nftables sets with the provided elements.
func (c *Controller) Apply(allowed, blocked SetElements) error {
    c.mu.Lock()
    defer c.mu.Unlock()

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
        return fmt.Errorf("failed to apply nftables transaction: %w", err)
    }

    return nil
}

// addElements converts IPs/MACs to nftables.SetElement and adds them.
func (c *Controller) addElements(setName string, items interface{}) error {
    set := c.sets[setName]
    var elements []nftables.SetElement

    switch v := items.(type) {
    case []net.IP:
        for _, ip := range v {
            // Ensure 4-byte representation for IPv4
            elements = append(elements, nftables.SetElement{Key: ip.To4()})
        }
    case []net.HardwareAddr:
        for _, mac := range v {
            elements = append(elements, nftables.SetElement{Key: mac})
        }
    default:
        return fmt.Errorf("unsupported element type")
    }

    if len(elements) > 0 {
        if err := c.conn.SetAddElements(set, elements); err != nil {
            return fmt.Errorf("failed to add elements to set %s: %w", setName, err)
        }
    }
    return nil
}

// Unused but required to satisfy unix import in some nftables contexts
var _ = unix.NFT_MSG_NEWSET
