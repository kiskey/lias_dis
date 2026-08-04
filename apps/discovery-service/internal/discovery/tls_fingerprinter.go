// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/tls_fingerprinter.go
// Version: 1.4 (Enhanced TLS Fingerprinting)
package discovery

import (
    "context"
    "crypto/sha256"
    "crypto/tls"
    "encoding/hex"
    "fmt"
    "net"
    "strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

type TLSFingerprinter struct {
    ctx    context.Context
    cancel context.CancelFunc
}

func NewTLSFingerprinter() *TLSFingerprinter {
    return &TLSFingerprinter{}
}

func (e *TLSFingerprinter) Name() string { return "tls" }

func (e *TLSFingerprinter) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

func (e *TLSFingerprinter) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

func (e *TLSFingerprinter) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }

    addr := net.JoinHostPort(d.CurrentIP, "443")
    
    dialer := &net.Dialer{Timeout: 2 * time.Second}

    serverName := d.Hostname
    if serverName == "" {
        serverName = d.CurrentIP
    }

    config := &tls.Config{
        InsecureSkipVerify: true,
        ServerName:         serverName,
        MinVersion:         tls.VersionTLS10,
        MaxVersion:         tls.VersionTLS13,
    }

    handshakeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()

    conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
    if err != nil {
        return nil, nil
    }
    defer conn.Close()

    if deadline, ok := handshakeCtx.Deadline(); ok {
        _ = conn.SetDeadline(deadline)
    }

    state := conn.ConnectionState()

    enr := &models.Enrichment{
        Source:     e.Name(),
        Confidence: 0.70,
        Raw:        make(map[string]interface{}),
    }

    if len(state.ServerName) > 0 {
        enr.Raw["sni"] = state.ServerName
        if enr.Hostname == "" {
            enr.Hostname = state.ServerName
        }
    }

    if len(state.PeerCertificates) > 0 {
        cert := state.PeerCertificates[0]
        
        // Hash the cert for provenance, but exclude expiry/serial for a stable config fingerprint
        h := sha256.New()
        h.Write([]byte(fmt.Sprintf("%d|%d|%s|%s|%s", state.Version, state.CipherSuite, state.NegotiatedProtocol, cert.Subject.String(), cert.Issuer.String())))
        enr.Raw["tls_server_fingerprint"] = hex.EncodeToString(h.Sum(nil))
        
        // Extract SANs (Subject Alternative Names) for better device identification
        if len(cert.DNSNames) > 0 {
            enr.Raw["san"] = strings.Join(cert.DNSNames, ",")
            if enr.Hostname == "" {
                enr.Hostname = cert.DNSNames[0]
            }
        }
        
        issuer := cert.Issuer.CommonName
        subject := cert.Subject.CommonName
        
        if containsAny(subject, "Android", "android") {
            enr.Model = "Android"
            enr.DeviceType = "phone"
        } else if containsAny(subject, "iPhone", "iPad", "iOS") {
            enr.Model = "iOS"
            enr.DeviceType = "phone"
        } else if containsAny(issuer, "Windows", "Microsoft") {
            enr.Model = "Windows"
            enr.DeviceType = "pc"
        }
    }

    switch state.Version {
    case tls.VersionTLS10:
        enr.Raw["tls_version"] = "1.0"
    case tls.VersionTLS11:
        enr.Raw["tls_version"] = "1.1"
    case tls.VersionTLS12:
        enr.Raw["tls_version"] = "1.2"
    case tls.VersionTLS13:
        enr.Raw["tls_version"] = "1.3"
    }

    if len(enr.Raw) > 0 {
        return enr, nil
    }

    return nil, nil
}

func containsAny(s string, subs ...string) bool {
    for _, sub := range subs {
        if len(s) >= len(sub) && s[:len(sub)] == sub {
            return true
        }
    }
    return false
}
