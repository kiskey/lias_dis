package discovery

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"testing"
	"time"
)

func TestTLSMetadataHasCorrectSemantics(t *testing.T) {
	cert := &x509.Certificate{
		Raw:       []byte("certificate-der"),
		Subject:   pkix.Name{CommonName: "Android iPhone misleading text"},
		Issuer:    pkix.Name{CommonName: "Local CA"},
		DNSNames:  []string{"device.home.arpa"},
		NotBefore: time.Unix(1, 0),
		NotAfter:  time.Unix(2, 0),
	}
	enr := tlsMetadataFromState(tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
		PeerCertificates:   []*x509.Certificate{cert},
	})
	if enr.Source != "tls_metadata" || enr.Hostname != "" || enr.Model != "" || enr.DeviceType != "" {
		t.Fatalf("TLS metadata incorrectly emitted identity/classification fields: %#v", enr)
	}
	if got := enr.Raw["observation_role"]; got != "dis_tls_client" {
		t.Fatalf("unexpected observation role: %v", got)
	}
	if got := enr.Raw["identity_evidence"]; got != false {
		t.Fatalf("TLS metadata incorrectly marked as identity evidence: %v", got)
	}
	digest := sha256.Sum256(cert.Raw)
	if got := enr.Raw["server_certificate_sha256"]; got != hex.EncodeToString(digest[:]) {
		t.Fatalf("certificate digest mismatch: %v", got)
	}
}

func TestTLSServerNameRejectsGenericOrUnsafeValues(t *testing.T) {
	if got := tlsServerName("printer.home.arpa."); got != "printer.home.arpa" {
		t.Fatalf("valid SNI name rejected: %q", got)
	}
	for _, value := range []string{"", "192.168.1.2", "iphone", "bad name", "x/y"} {
		if got := tlsServerName(value); got != "" {
			t.Fatalf("unsafe/generic SNI accepted: %q -> %q", value, got)
		}
	}
}
