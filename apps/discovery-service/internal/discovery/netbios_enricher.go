// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/netbios_enricher.go
// Version: 1.1
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
type NetBIOSEnricher struct {
    ctx    context.Context
    cancel context.CancelFunc
}

func NewNetBIOSEnricher() *NetBIOSEnricher {
    return &NetBIOSEnricher{}
}

func (e *NetBIOSEnricher) Name() string { return "netbios" }

func (e *NetBIOSEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

func (e *NetBIOSEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

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
        Confidence: 0.6,
        Raw:        make(map[string]interface{}),
    }

    var services []string
    for _, n := range names {
        if n.Suffix == 0x00 && n.Flags&0x8000 == 0 && enr.Hostname == "" {
            enr.Hostname = n.Name
        }
        if n.Suffix == 0x1C {
            services = append(services, "domain_controller")
        }
        if n.Suffix == 0x20 {
            services = append(services, "file_server")
        }
    }

    if len(services) > 0 {
        enr.Services = services
    }

    if enr.Hostname == "" && len(names) > 0 {
        enr.Hostname = names[0].Name
    }

    if enr.Hostname != "" || len(services) > 0 {
        return enr, nil
    }

    return nil, nil
}

type netbiosName struct {
    Name   string
    Suffix byte
    Flags  uint16
}

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

    req := make([]byte, 50)
    
    // TID: 0x0001
    binary.BigEndian.PutUint16(req[0:2], 0x0001)
    // MATH-04 Fix: Flags: 0x0000 (Standard query, no reserved bits set)
    binary.BigEndian.PutUint16(req[2:4], 0x0000)
    // Questions: 1
    binary.BigEndian.PutUint16(req[4:6], 1)
    
    name := []byte("*               \x00")
    req[12] = 32 // Length of encoded name
    encodeNetBIOSName(name, req[13:45])
    
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

func encodeNetBIOSName(name []byte, dst []byte) {
    for i := 0; i < 16; i++ {
        c := name[i]
        dst[i*2] = 'A' + (c >> 4)
        dst[i*2+1] = 'A' + (c & 0x0F)
    }
}

func parseNodeStatusResponse(data []byte) ([]netbiosName, error) {
    // MATH-03 Fix: Corrected off-by-one parsing offsets for NBSTAT response.
    // Header(12) + Name Length(1) + Encoded Name(32) + Null(1) + Type(2) + Class(2) + TTL(4) = 54
    if len(data) < 57 {
        return nil, fmt.Errorf("packet too short")
    }

    // RDLENGTH is at offset 54-55
    dataLen := binary.BigEndian.Uint16(data[54:56])
    if dataLen == 0 {
        return nil, nil
    }

    // NUMNAMES is at offset 56
    numNames := int(data[56])
    if 57+numNames*18 > len(data) {
        return nil, fmt.Errorf("malformed netbios response")
    }

    var names []netbiosName
    offset := 57
    for i := 0; i < numNames; i++ {
        entry := data[offset : offset+18]
        n := netbiosName{
            Name:   string(entry[0:15]),
            Suffix: entry[15],
            Flags:  binary.BigEndian.Uint16(entry[16:18]),
        }
        n.Name = string(bytes.TrimRight([]byte(n.Name), " "))
        names = append(names, n)
        offset += 18
    }

    return names, nil
}
