# LIAS & DIS

**LAN Internet Access Scheduler (LIAS)** + **Discovery Intelligence Service (DIS)**

Two independent static Go binaries that work together to provide real-time network device discovery and policy-based firewall scheduling on Linux networks.

## Architecture

- **DIS (Discovery Intelligence Service):** Runs on a host with Layer-2 visibility (e.g., Proxmox host). Observes the network via netlink, IEEE OUI lookups, Pi-hole v6, and DHCP. Correlates devices and exposes a REST/SSE API on `:8080`.
- **LIAS (LAN Internet Access Scheduler):** Runs on the VPN Gateway / Router. Consumes DIS data in real-time over SSE, evaluates policy precedence and time schedules, persists configuration to a pure-Go SQLite database, and manipulates an isolated `netdev lancontrol` nftables table to enforce access rules.

## Features & Audit Hardening
- **Zero CGO:** Compiles 100% statically with `CGO_ENABLED=0` for `linux/amd64` and `linux/arm64`.
- **Deterministic Device Identity (PDID):** Stable hardware identity tracking across service restarts.
- **Embedded IEEE OUI Lookup:** Built-in MAC vendor database for instant hardware identification.
- **Isolated Netfilter Architecture:** Operates strictly within `table netdev lancontrol` on ingress (`eth0`). Never alters system routing, NAT, or `sing-box` rules.
- **Overnight Schedule Engine:** Supports cross-midnight time rules (e.g., 22:00 to 06:00 bedtime schedules).
- **Persistent Storage:** Integrated pure-Go SQLite storage (`/var/lib/lias/state.db`).
- **Apple HIG Embedded Web Dashboard:** Embedded SPA served directly from the LIAS binary (`:8081`).

## Prerequisites

- Go 1.23+
- Linux kernel 5.10+ (for `netdev` ingress hooks)
- `nftables` utility and `CAP_NET_ADMIN` capability for LIAS
- `nmap`, `avahi-tools` (optional, for DIS enrichment)

## Build

Both binaries are compiled statically without external C library dependencies.

```bash
# Build for host architecture
make build

# Cross-compile for linux/amd64 and linux/arm64
make release
```

Binaries will be placed in the `bin/` directory.

## Configuration

### DIS Config (`/etc/dis/config.yaml`)
```yaml
# ==============================================================================
# Discovery Intelligence Service (DIS) Configuration
# Version: 1.4
# File: /etc/dis/config.yaml
# ==============================================================================

# HTTP Server Settings for the DIS REST API and SSE Event Stream
http:
  listen: ":8080"            # Address and port to bind (default: ":8080")
  auth_token: ""             # Optional Bearer token for API authentication (empty = open LAN)

# Network Discovery & Observation Providers
discovery:
  interface: "eth0"          # Primary network interface to monitor (default: "eth0")

  # Real-time Kernel Netlink Provider (ARP/NDP table subscription)
  netlink:
    enabled: true            # Enable real-time kernel netlink neighbor monitoring

  # Pi-hole v6 API Activity Intelligence Provider
  pihole:
    enabled: true            # Enable polling active DNS clients from Pi-hole
    url: "http://pi.hole"    # Pi-hole v6 base API URL (e.g., http://192.168.1.2 or http://pi.hole)
    password: "your_pihole_password" # Pi-hole web password (used for /api/auth session tokens)

  # DHCP Lease File Provider
  dhcp:
    enabled: true            # Enable reading DHCP leases to map hostnames and IPs
    type: "router"           # DHCP server type: "router", "pihole", "dnsmasq", or "kea"
    
    # Select ONE of the 3 data source strategies below:
    # --------------------------------------------------------------------------
    # Option A: Remote SSH Execution (Recommended for OpenWrt/Routers)
    ssh_host: "192.168.1.1"  # Router IP to fetch /tmp/dhcp.leases via SSH key
    ssh_user: "root"         # SSH username (default: "root")
    
    # Option B: Remote HTTP URL Fetching
    lease_url: ""            # e.g., "http://192.168.1.1/dhcp.leases"
    
    # Option C: Local File Path (If DIS runs on the router itself or uses NFS)
    lease_file: "/tmp/dhcp.leases"

  # On-Demand Device Fingerprinting & Enrichment Pipeline
  enrichment:
    avahi_enabled: true       # Enable mDNS service discovery via system avahi-browse
    ssdp_enabled: true        # Enable native Go UPnP multicast M-SEARCH discovery
    netbios_enabled: true     # Enable UDP port 137 NetBIOS node status queries
    nmap_enabled: true        # Enable Nmap port and OS fingerprinting fallback
    unknown_device_scan: true # Automatically trigger enrichment for unclassified devices
    validation_interval: "24h"# Periodic re-validation check interval for known devices (default: "24h")

# Logging Output Settings
logging:
  level: "info"              # Log verbosity: "debug", "info", "warn", or "error" (default: "info")
  format: "json"             # Log format: "json" or "text" (default: "json")
```

### LIAS Config (`/etc/lias/config.yaml`)
```yaml
# ==============================================================================
# LAN Internet Access Scheduler (LIAS) Configuration
# Version: 1.5
# File: /etc/lias/config.yaml
# ==============================================================================

# HTTP Server Settings for the LIAS API and Embedded Apple HIG Web Dashboard
http:
  listen: ":8081"            # Address and port to bind (default: ":8081")

# Discovery Intelligence Service (DIS) Connection Settings
dis:
  url: "http://192.168.1.10" # DIS server IP or hostname (DIS port :8080 is targeted automatically)
  auth_token: ""             # Bearer auth token if configured in DIS
  sync_interval: "30s"       # Background REST poll interval fallback (default: "30s")

# Isolated Netfilter Architecture (netdev ingress table)
nftables:
  interface: "eth0"          # LAN-facing network interface to apply packet filtering (default: "eth0")
  table_name: "lancontrol"   # Isolated netdev table name (default: "lancontrol")
  shutdown_behavior: "flush" # Action on SIGTERM shutdown: "flush" (remove table) or "persist" (keep rules)

# Schedule Engine Evaluation Defaults
schedules:
  timezone: "UTC"            # Default IANA timezone (e.g. "America/Los_Angeles", "Europe/London", "UTC")

# CGO-Free Pure-Go SQLite Persistent Storage Engine
storage:
  path: "/var/lib/lias/state.db" # Database file path for persisting Tags, Policies, and Schedules

# Logging Output Settings
logging:
  level: "info"              # Log verbosity: "debug", "info", "warn", or "error" (default: "info")
  format: "json"             # Log format: "json" or "text" (default: "json")
```

## Deployment

1. Place the `dis` binary on your Proxmox host or primary switch/router.
2. Place the `lias` binary on your VPN Gateway / Router.
3. Copy the respective `config.yaml` files to `/etc/dis/` and `/etc/lias/`.
4. Run via systemd or supervisor:
   ```bash
   ./dis -config /etc/dis/config.yaml
   ./lias -config /etc/lias/config.yaml
   ```

## Dashboard

The LIAS Web UI is embedded in the `lias` binary and accessible at `http://<lias-ip>:8081/`. It provides real-time device management, tag assignments, time schedule creation, and firewall rule status.
```

---

### Final Remediation & Validation Summary

| Issue / Gap ID | Severity | File(s) Affected | Status |
|---|---|---|---|
| **GAP-01** | CRITICAL | `apps/lias/web/src/main.js`, `api.js` | ✅ **RESOLVED** (Batch 8) — Implemented complete SPA controller, router, and real-time toast alerts. |
| **GAP-02** | CRITICAL | `apps/lias/internal/sync/dis_client.go` | ✅ **RESOLVED** (Batch 4) — Real-time SSE parser extracts `pdid`/`device_id` from event payloads. |
| **GAP-03** | CRITICAL | `apps/lias/internal/nftables/controller.go` | ✅ **RESOLVED** (Batch 6) — Corrected Source MAC payload offset to `Offset: 6`. |
| **GAP-04** | CRITICAL | `apps/lias/internal/nftables/controller.go` | ✅ **RESOLVED** (Batch 6) — Restored mandatory `Device: eth0` interface binding on netdev ingress chain. |
| **GAP-05** | CRITICAL | `apps/lias/internal/storage/sqlite.go`, `cmd/lias/main.go` | ✅ **RESOLVED** (Batch 7 & 9) — CGO-free pure-Go SQLite engine persists Tags, Policies, and Schedules. |
| **GAP-06** | CRITICAL | `apps/discovery-service/internal/inventory/pdid.go` | ✅ **RESOLVED** (Batch 1) — Removed `UnixNano()` seed to guarantee deterministic PDID hashes. |
| **GAP-07** | HIGH | `apps/lias/internal/schedule/parser.go` | ✅ **RESOLVED** (Batch 5) — Cross-midnight time rules (22:00–06:00) supported cleanly. |
| **GAP-08** | HIGH | `apps/lias/internal/schedule/parser.go` | ✅ **RESOLVED** (Batch 5) — Replaced 10,080 minute loop with direct transition calculations. |
| **GAP-09** | HIGH | `apps/discovery-service/internal/discovery/netlink_provider.go` | ✅ **RESOLVED** (Batch 1) — Cached interface indices and added `unix.NUD_*` neighbor state filters. |
| **GAP-10** | HIGH | `apps/lias/internal/nftables/controller.go` | ✅ **RESOLVED** (Batch 6) — Added `FlushChain` call prior to appending netfilter rules. |
| **OUI-01** | HIGH | `pkg/oui/oui.go` | ✅ **RESOLVED** (Batch 1 & 7) — Implemented embedded IEEE OUI vendor database. |
| **MOD-01** | MEDIUM | `shared/go.mod` | ✅ **RESOLVED** (Batch 4) — Defined proper module boundary for `shared`. |
| **MAKE-01** | LOW | `Makefile` | ✅ **RESOLVED** (Batch 8) — Removed `go mod tidy` state mutation from build targets. |

**Project Status:** All critical, high, and medium priority failures, gaps, and specification bugs have been systematically refactored, tested, and validated. The repository is fully ready for static build (`CGO_ENABLED=0`) and production deployment.
