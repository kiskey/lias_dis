// Package discovery provides bounded TLS server-metadata enrichment.
//
// File:    apps/discovery-service/internal/discovery/tls_fingerprinter.go
// Version: 2.0 (Correct Client/Server Semantics; No Identity Classification)
package discovery

import (
    "context"
    "crypto/sha256"
    "crypto/tls"
	"crypto/x509"
    "encoding/hex"
    "fmt"
    "net"
    "strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// TLSMetadataEnricher records metadata from one DIS-as-client TLS handshake.
// Negotiated parameters depend on both peers and are not a stable device or OS
// fingerprint, so this enricher never emits identity/classification fields.
type TLSMetadataEnricher struct {
    ctx    context.Context
    cancel context.CancelFunc
}

// TLSFingerprinter remains an alias for source compatibility. The corrected
// name should be used by new code.
type TLSFingerprinter = TLSMetadataEnricher

func NewTLSMetadataEnricher() *TLSMetadataEnricher { return &TLSMetadataEnricher{} }

func NewTLSFingerprinter() *TLSMetadataEnricher { return NewTLSMetadataEnricher() }

func (e *TLSMetadataEnricher) Name() string { return "tls_metadata" }

func (e *TLSMetadataEnricher) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("TLS metadata enricher requires a non-nil context")
	}
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

func (e *TLSMetadataEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

func (e *TLSMetadataEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }
	ip := net.ParseIP(strings.TrimSpace(d.CurrentIP))
	if !isLANAddress(ip) {
		return nil, fmt.Errorf("refusing TLS metadata connection to non-LAN IP %q", d.CurrentIP)
    }

	serverName := tlsServerName(d.Hostname)
    config := &tls.Config{
		// LAN services commonly use private/self-signed certificates. We collect
		// metadata only and explicitly report that verification was disabled.
		InsecureSkipVerify: true, // #nosec G402 -- intentional metadata probe
        ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
        MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
    }
    handshakeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 2 * time.Second},
		Config:    config,
	}
	conn, err := dialer.DialContext(handshakeCtx, "tcp", net.JoinHostPort(ip.String(), "443"))
    if err != nil {
        return nil, nil
    }
    defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, nil
    }
	return tlsMetadataFromState(tlsConn.ConnectionState()), nil
    }

func tlsMetadataFromState(state tls.ConnectionState) *models.Enrichment {
	raw := map[string]interface{}{
		"observation_role":        "dis_tls_client",
		"identity_evidence":       false,
		"certificate_verified":    false,
		"negotiated_tls_version":  tls.VersionName(state.Version),
		"negotiated_cipher_suite": tls.CipherSuiteName(state.CipherSuite),
        }
	if state.NegotiatedProtocol != "" {
		raw["negotiated_alpn"] = boundedText(state.NegotiatedProtocol, 64)
    }
    if len(state.PeerCertificates) > 0 {
		addCertificateMetadata(raw, state.PeerCertificates[0])
	}
	return &models.Enrichment{
		Source:     "tls_metadata",
		Confidence: 0.35,
		Raw:        raw,
	}
}
        
func addCertificateMetadata(raw map[string]interface{}, cert *x509.Certificate) {
	if cert == nil {
		return
	}
	digest := sha256.Sum256(cert.Raw)
	raw["server_certificate_sha256"] = hex.EncodeToString(digest[:])
	raw["server_certificate_subject_cn"] = boundedText(cert.Subject.CommonName, 256)
	raw["server_certificate_issuer_cn"] = boundedText(cert.Issuer.CommonName, 256)
	raw["server_certificate_not_before"] = cert.NotBefore.UTC().Format(time.RFC3339)
	raw["server_certificate_not_after"] = cert.NotAfter.UTC().Format(time.RFC3339)
        if len(cert.DNSNames) > 0 {
		limit := len(cert.DNSNames)
		if limit > 16 {
			limit = 16
            }
		names := make([]string, 0, limit)
		for _, name := range cert.DNSNames[:limit] {
			names = append(names, boundedText(name, 253))
        }
		raw["server_certificate_dns_names"] = names
        }
    }

func tlsServerName(hostname string) string {
	hostname = strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	if hostname == "" || net.ParseIP(hostname) != nil || isGenericHostname(hostname) {
		return ""
    }
	if len(hostname) > 253 || strings.ContainsAny(hostname, " /\\\t\r\n") {
		return ""
    }
	return hostname
}

// containsAny is retained for compatibility with older package tests.
func containsAny(s string, subs ...string) bool {
	s = strings.ToLower(s)
    for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
            return true
        }
    }
    return false
}
