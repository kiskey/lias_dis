// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netbios_enricher.go
// Version: 1.0
package discovery

import (
    "bytes"
    "context"
    "encoding/binary"
    "fmt"
    "net"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// NetBIOSEnricher sends a native NetBIOS Node Status request (UDP port 137)
// to resolve Windows hostnames and workgroups.
// See §3.5 for details.
type NetBIOSEnricher struct {
    ctx    context.Context
    cancel context.CancelFunc
}

// NewNetBIOSEnricher initializes the enricher.
func NewNetBIOSEnricher() *NetBIOSEnricher {
    return &NetBIOSEnricher{}
}

// Name returns the provider's identifier.
func (e *NetBIOSEnricher) Name() string { return "netbios" }

// Start satisfies the Provider interface.
func (e *NetBIOSEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

// Stop satisfies the Provider interface.
func (e *NetBIOSEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

// Enrich queries the target device for its NetBIOS names table.
func (e *NetBIOSEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }

    names, err := e.queryNodeStatus(ctx, d.CurrentIP)
    if err != nil || len(names) == 0 {
        return nil, nil
    }

    enr := &models.Enrichment{
        Source:     e.Name(),
        Confidence: 0.6, // Medium-High confidence for NetBIOS
        Raw:        make(map[string]interface{}),
    }

    var services []string
    for _, n := range names {
        // NetBIOS suffix 0x00 (Workstation Service) usually indicates the hostname
        if n.Suffix == 0x00 && n.Flags&0x8000 == 0 && enr.Hostname == "" {
            enr.Hostname = n.Name
        }
        // Suffix 0x1C indicates Domain Controllers
        if n.Suffix == 0x1C {
            services = append(services, "domain_controller")
        }
        // Suffix 0x20 (File Server Service)
        if n.Suffix == 0x20 {
            services = append(services, "file_server")
        }
    }

    if len(services) > 0 {
        enr.Services = services
    }

    if enr.Hostname == "" && len(names) > 0 {
        // Fallback to the first unique name if 0x00 wasn't found
        enr.Hostname = names[0].Name
    }

    if enr.Hostname != "" || len(services) > 0 {
        return enr, nil
    }

    return nil, nil
}

// netbiosName represents a parsed entry from the NetBIOS Node Status response.
type netbiosName struct {
    Name   string
    Suffix byte
    Flags  uint16
}

// queryNodeStatus constructs and sends a NetBIOS NS Node Status Request.
func (e *NetBIOSEnricher) queryNodeStatus(ctx context.Context, ip string) ([]netbiosName, error) {
    searchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()

    addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ip, "137"))
    if err != nil {
        return nil, err
    }

    conn, err := net.DialUDP("udp4", nil, addr)
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    deadline, _ := searchCtx.Deadline()
    _ = conn.SetReadDeadline(deadline)

    // Construct NetBIOS Node Status Request packet
    // Transaction ID (2 bytes) + Flags (2 bytes) + Questions (2) + Answers (2) +
    // Authority (2) + Additional (2) + Name (34 bytes) + Type (2) + Class (2)
    req := make([]byte, 50)
    
    // TID: 0x0001
    binary.BigEndian.PutUint16(req[0:2], 0x0001)
    // Flags: 0x0010 (Standard query, Node Status)
    binary.BigEndian.PutUint16(req[2:4], 0x0010)
    // Questions: 1
    binary.BigEndian.PutUint16(req[4:6], 1)
    // Answers, Authority, Additional: 0
    
    // NetBIOS Name: "*" encoded as a level-1 NetBIOS name
    // "*" padded to 15 chars with spaces, then 16th char is 0x00
    name := []byte("*               \x00")
    // Encode to DNS format (length + encoded halves)
    req[12] = 32 // Length of encoded name
    encodeNetBIOSName(name, req[13:45])
    
    // Null terminator
    req[45] = 0
    // Type: NBSTAT (0x21)
    binary.BigEndian.PutUint16(req[46:48], 0x0021)
    // Class: IN (0x01)
    binary.BigEndian.PutUint16(req[48:50], 0x0001)

    if _, err = conn.Write(req); err != nil {
        return nil, err
    }

    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return nil, err
    }

    return parseNodeStatusResponse(buf[:n])
}

// encodeNetBIOSName converts a 16-byte NetBIOS name into the 32-byte half-ASCII representation.
func encodeNetBIOSName(name []byte, dst []byte) {
    for i := 0; i < 16; i++ {
        c := name[i]
        dst[i*2] = 'A' + (c >> 4)
        dst[i*2+1] = 'A' + (c & 0x0F)
    }
}

// parseNodeStatusResponse parses the raw UDP response from a NetBIOS Node Status query.
func parseNodeStatusResponse(data []byte) ([]netbiosName, error) {
    if len(data) < 57 {
        return nil, fmt.Errorf("packet too short")
    }

    // The response header is 12 bytes. Then the queried name (34 bytes + null = 35).
    // Then Type (2) + Class (2) + TTL (4) + Data Length (2).
    // The data length field is at offset 12 + 35 + 8 = 55
    dataLen := binary.BigEndian.Uint16(data[55:57])
    if dataLen == 0 {
        return nil, nil
    }

    // Number of names (1 byte)
    numNames := int(data[57])
    if 58+numNames*18 > len(data) {
        return nil, fmt.Errorf("malformed netbios response")
    }

    var names []netbiosName
    offset := 58
    for i := 0; i < numNames; i++ {
        entry := data[offset : offset+18]
        n := netbiosName{
            Name:   string(entry[0:15]), // 15 chars
            Suffix: entry[15],           // 16th char
            Flags:  binary.BigEndian.Uint16(entry[16:18]),
        }
        // Clean trailing spaces from name
        n.Name = string(bytes.TrimRight([]byte(n.Name), " "))
        names = append(names, n)
        offset += 18
    }

    return names, nil
}
