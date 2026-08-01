// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/ssdp_enricher.go
// Version: 1.0
package discovery

import (
    "context"
    "encoding/xml"
    "fmt"
    "log/slog"
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// SSDPEnricher uses native Go multicast UDP to discover UPnP devices.
// It sends an M-SEARCH, listens for responses, and fetches the XML
// descriptor at the LOCATION header.
// See §3.5 for details.
type SSDPEnricher struct {
    ctx    context.Context
    cancel context.CancelFunc
}

// NewSSDPEnricher initializes the enricher.
func NewSSDPEnricher() *SSDPEnricher {
    return &SSDPEnricher{}
}

// Name returns the provider's identifier.
func (e *SSDPEnricher) Name() string { return "ssdp" }

// Start satisfies the Provider interface.
func (e *SSDPEnricher) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    return nil
}

// Stop satisfies the Provider interface.
func (e *SSDPEnricher) Stop() error {
    if e.cancel != nil {
        e.cancel()
    }
    return nil
}

// Enrich broadcasts an SSDP M-SEARCH, waits for responses, and if a response
// is received from the target device's IP, fetches and parses the XML descriptor.
func (e *SSDPEnricher) Enrich(ctx context.Context, d *models.Device) (*models.Enrichment, error) {
    if d == nil || d.CurrentIP == "" {
        return nil, fmt.Errorf("cannot enrich without IP")
    }

    location, err := e.searchSSDP(ctx, d.CurrentIP)
    if err != nil || location == "" {
        return nil, nil // No SSDP response from this IP
    }

    // Fetch the device descriptor
    enr, err := e.fetchDescriptor(ctx, location)
    if err != nil {
        return nil, err
    }
    return enr, nil
}

// searchSSDP sends an M-SEARCH packet and waits for a response from the target IP.
func (e *SSDPEnricher) searchSSDP(ctx context.Context, targetIP string) (string, error) {
    // Set a short timeout for the multicast search
    searchCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()

    addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
    if err != nil {
        return "", err
    }

    conn, err := net.ListenPacket("udp4", ":0")
    if err != nil {
        return "", err
    }
    defer conn.Close()

    // Set read deadline to match context
    deadline, _ := searchCtx.Deadline()
    _ = conn.SetReadDeadline(deadline)

    msg := []byte("M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 2\r\n" +
        "ST: ssdp:all\r\n\r\n")

    if _, err = conn.WriteTo(msg, addr); err != nil {
        return "", err
    }

    buf := make([]byte, 4096)
    for {
        n, src, err := conn.ReadFrom(buf)
        if err != nil {
            if searchCtx.Err() != nil {
                return "", nil // Timed out, no response
            }
            return "", err
        }

        // Check if the response came from our target device
        if srcIP, ok := src.(*net.UDPAddr); ok && srcIP.IP.String() == targetIP {
            headers := string(buf[:n])
            return parseLocation(headers), nil
        }
    }
}

// parseLocation extracts the LOCATION header value from an SSDP response.
func parseLocation(headers string) string {
    lines := strings.Split(headers, "\r\n")
    for _, line := range lines {
        if strings.HasPrefix(strings.ToLower(line), "location:") {
            return strings.TrimSpace(line[len("location:"):])
        }
    }
    return ""
}

// fetchDescriptor downloads and parses the UPnP device descriptor XML.
func (e *SSDPEnricher) fetchDescriptor(ctx context.Context, url string) (*models.Enrichment, error) {
    client := &http.Client{Timeout: 5 * time.Second}
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("ssdp descriptor returned non-200: %d", resp.StatusCode)
    }

    var dev struct {
        XMLName     xml.Name `xml:"root"`
        Device      struct {
            FriendlyName string `xml:"friendlyName"`
            Manufacturer string `xml:"manufacturer"`
            ModelName    string `xml:"modelName"`
            ModelNumber  string `xml:"modelNumber"`
            DeviceType   string `xml:"deviceType"`
        } `xml:"device"`
    }

    if err := xml.NewDecoder(resp.Body).Decode(&dev); err != nil {
        slog.Debug("Failed to parse SSDP XML", "url", url, "error", err)
        return nil, nil
    }

    enr := &models.Enrichment{
        Source:       e.Name(),
        Confidence:   0.8, // High confidence for device self-reporting
        FriendlyName: dev.Device.FriendlyName,
        Manufacturer: dev.Device.Manufacturer,
        Model:        dev.Device.ModelName,
        Raw: map[string]interface{}{
            "device_type":  dev.Device.DeviceType,
            "model_number": dev.Device.ModelNumber,
        },
    }
    
    // Infer device type from UPnP type
    if strings.Contains(dev.Device.DeviceType, "MediaRenderer") {
        enr.DeviceType = "tv"
    } else if strings.Contains(dev.Device.DeviceType, "MediaServer") {
        enr.DeviceType = "server"
    }

    return enr, nil
}
