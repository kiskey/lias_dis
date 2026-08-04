// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/tls_fingerprinter.go
// Version: 1.2
package discovery

import (
    "context"
    "crypto/sha256"
    "crypto/tls"
    "fmt"
    "net"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// TLSFingerprinter actively probes port 443 to gather TLS SNI and certificate data.
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
    
    // Resource efficiency: Dialer with strict 2-second connection timeout
    dialer := &net.Dialer{Timeout: 2 * time.Second}

    // Accuracy: Provide ServerName to ensure the server responds with the correct cert
    serverName := d.Hostname
    if serverName == "" {
        serverName = d.CurrentIP
    }

    config := &tls.Config{
        InsecureSkipVerify: true, // We only care about the certificate structure, not trust
        ServerName:         serverName,
        MinVersion:         tls.VersionTLS10,
        MaxVersion:         tls.VersionTLS13,
    }

    // Resource efficiency: Hard cap the TLS handshake to 3 seconds
    handshakeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()

    conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
    if err != nil {
        return nil, nil // Device likely doesn't run HTTPS or timed out
    }
    defer conn.Close()

    // Ensure handshake completes within the context deadline
    if deadline, ok := handshakeCtx.Deadline(); ok {
        _ = conn.SetDeadline(deadline)
    }

    state := conn.ConnectionState()

    enr := &models.Enrichment{
        Source:     e.Name(),
        Confidence: 0.70, // High confidence for direct TLS OS inference
        Raw:        make(map[string]interface{}),
    }

    // 1. Extract SNI (Server Name Indication) if present
    if len(state.ServerName) > 0 {
        enr.Raw["sni"] = state.ServerName
        if enr.Hostname == "" {
            enr.Hostname = state.ServerName
        }
    }

    // 2. Simple Hash of the first certificate chain
    if len(state.PeerCertificates) > 0 {
        cert := state.PeerCertificates[0]
        hash := sha256.Sum256(cert.Raw)
        enr.Raw["cert_sha256"] = fmt.Sprintf("%x", hash[:16])
        
        // Infer OS from Issuer/Common Name patterns
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

    // 3. TLS Version Fingerprinting
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
