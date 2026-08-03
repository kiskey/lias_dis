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
# Version: 1.3
# File Path: /etc/dis/config.yaml
# ==============================================================================

# HTTP REST API and SSE Event Stream Server Settings
http:
  listen: ":8080"            # Address and port to bind (default: ":8080")
  auth_token: ""             # Optional Bearer token for API authentication (empty = open LAN)

# Network Discovery & Observation Providers
discovery:
  interface: "eth0"          # Primary LAN network interface to monitor (default: "eth0")

  # Real-time Kernel Netlink Provider (ARP/NDP table subscription)
  netlink:
    enabled: true            # Enable real-time netlink neighbor monitoring

  # Pi-hole v6 API Activity Intelligence Provider
  pihole:
    enabled: true            # Enable polling active DNS clients from Pi-hole
    url: "http://pi.hole"    # Pi-hole v6 base API URL (e.g., http://192.168.1.2 or http://pi.hole)
    password: "your_pihole_password" # Pi-hole web/app password (used for /api/auth session token)

  # DHCP Lease File Provider
  dhcp:
    enabled: true            # Enable reading DHCP leases to map hostnames, IPs, and MACs
    type: "router"           # DHCP server type: "router", "pihole", "dnsmasq", or "kea"
    
    # Select ONE of the data source options below:
    # Option A: Local File Path (if DIS runs on the router itself or uses NFS)
    lease_file: "/tmp/dhcp.leases"
    
    # Option B: Remote HTTP URL Fetching
    lease_url: ""            # e.g., "http://192.168.1.1/dhcp.leases"
    
    # Option C: Remote SSH Execution (Recommended for OpenWrt/Routers)
    ssh_host: ""             # Router IP to fetch lease file via SSH (e.g., "192.168.1.1")
    ssh_user: "root"         # SSH username (default: "root")

  # On-Demand Device Fingerprinting & Enrichment Pipeline
  enrichment:
    avahi_enabled: true       # Enable mDNS service discovery via system avahi-browse
    ssdp_enabled: true        # Enable native Go UPnP multicast M-SEARCH discovery
    netbios_enabled: true     # Enable UDP port 137 NetBIOS node status queries
    nmap_enabled: true        # Enable Nmap port and OS fingerprinting fallback
    unknown_device_scan: true # Automatically trigger enrichment for unclassified devices
    validation_interval: "24h"# Periodic re-validation check interval for known devices

# CGO-Free Pure-Go SQLite Persistent Identity Engine
storage:
  path: "/var/lib/dis/state.db" # Database file path for persisting correlated device state

# Structured Logging Output Settings
logging:
  level: "info"              # Log verbosity: "debug", "info", "warn", or "error" (default: "info")
  format: "json"             # Log format: "json" or "text" (default: "json")
```

### LIAS Config (`/etc/lias/config.yaml`)
```yaml
# ==============================================================================
# LAN Internet Access Scheduler (LIAS) Configuration
# Version: 1.0
# File Path: /etc/lias/config.yaml
# ==============================================================================

# HTTP REST Server & Embedded Web UI Dashboard Settings
http:
  listen: ":8081"            # Address and port to bind (default: ":8081")

# Connection Parameters to Discovery Intelligence Service (DIS)
dis:
  url: "http://127.0.0.1:8080" # DIS server IP or URL (port :8080 targeted automatically)
  auth_token: ""             # Bearer auth token if configured in DIS
  sync_interval: "30s"       # Background REST polling fallback interval (default: "30s")

# Isolated Netfilter Architecture (netdev ingress table)
nftables:
  interface: "eth0"          # LAN-facing network interface to apply packet filtering (default: "eth0")
  table_name: "lancontrol"   # Isolated netdev table name (default: "lancontrol")
  shutdown_behavior: "flush" # Action on SIGTERM shutdown: "flush" (remove table) or "persist" (keep rules)

# Schedule Engine Evaluation Defaults
schedules:
  timezone: "UTC"            # Default IANA timezone (e.g., "America/Los_Angeles", "Europe/London", "UTC")

# CGO-Free Pure-Go SQLite Persistent Storage Engine
storage:
  path: "/var/lib/lias/state.db" # Database file path for persisting Tags, Policies, and Schedules

# Structured Logging Output Settings
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

# LIAS Multi-Schedule & Policy Management Guide

This document provides a comprehensive guide on how to use the multi-schedule policy system in LIAS (LAN Internet Access Scheduler), along with a visual reference of the policy precedence tree.

---

# Part 1: Understanding Schedules and Policies

LIAS decouples **Time Schedules** from **Access Policies**. This allows you to create modular time windows and attach them to different groups of devices.

## 1.1 Schedule Modes

When creating a schedule, you must choose a **Mode**. This determines the default behavior **outside** of the time windows you define.

### Downtime Mode

The rules you define act as **Block** windows.

Outside of these windows, traffic is **Allowed**.

**Example**

- Schedule: Bedtime
- Time: 22:00 → 06:00
- Result:
  - During the window → Internet **Blocked**
  - Outside the window → Internet **Allowed**

### Whitelist Mode

The rules you define act as **Allow** windows.

Outside of these windows, traffic is **Blocked**.

**Example**

- Schedule: Homework
- Time: 15:00 → 17:00
- Result:
  - During the window → Internet **Allowed**
  - Outside the window → Internet **Blocked**

---

## 1.2 The Multi-Schedule Advantage

Instead of trying to fit unrelated rules into a single schedule, LIAS allows multiple independent schedules to be attached to the same policy.

This provides several advantages:

- Modular schedules
- Easier maintenance
- Reusable schedules
- Automatic conflict detection
- Timeline preview before saving

The scheduler internally combines all attached schedules into one composite evaluation while ensuring conflicting rules cannot be saved.

---

# Part 2: Examples & Walkthroughs

## Example 1 — Kids Tag Group

Desired behavior:

1. Block Internet every night from **22:00–06:00**
2. Allow Internet only from **15:00–17:00** on weekdays

---

### Step 1 — Create Schedule A

**Name**

```
Bedtime
```

**Mode**

```
Downtime
```

**Days**

```
Mon Tue Wed Thu Fri Sat Sun
```

**Time**

```
22:00 → 06:00
```

**Action**

```
Block
```

---

### Step 2 — Create Schedule B

**Name**

```
Homework Allowance
```

**Mode**

```
Whitelist
```

**Days**

```
Mon Tue Wed Thu Fri
```

**Time**

```
15:00 → 17:00
```

**Action**

```
Allow
```

---

### Step 3 — Create Policy

Navigate to:

```
Policies
```

Click:

```
+ New Policy
```

### Step 1 — Target

Target Type

```
Tag Group
```

Tag

```
kids
```

Policy Name

```
Kids Internet Rules
```

---

### Step 2 — Enforcement

Action

```
Schedule-Driven
```

---

### Step 3 — Schedules

Attach

- Bedtime
- Homework Allowance

The UI automatically displays a merged timeline preview.

If any conflicting windows exist, the Save button remains disabled until the conflict is resolved.

Save the policy.

---

# Example 2 — IoT Tag Group

Desired behavior:

Completely block all IoT devices except for a firmware update window every night.

---

### Step 1 — Create Schedule

Name

```
IoT Update Window
```

Mode

```
Whitelist
```

Days

```
Sun Mon Tue Wed Thu Fri Sat
```

Time

```
02:00 → 02:30
```

Action

```
Allow
```

---

### Step 2 — Create Policy

Target

```
Tag Group
```

Tag

```
iot
```

Enforcement

```
Schedule-Driven
```

Attach

```
IoT Update Window
```

Save.

Because the schedule is Whitelist mode:

- Allowed for **30 minutes**
- Blocked for the remaining **23.5 hours**

---

# Part 3: Empty Schedule Safety Behavior

If a policy uses

```
Schedule-Driven
```

but **no schedules are attached**, LIAS defaults to:

```
ALLOW
```

This intentional **Default Open** behavior prevents accidental lockouts during initial installation.

Example:

- Install LIAS
- Global Policy = Schedule
- No schedules exist yet

Result:

```
Internet continues to work normally.
```

As soon as schedules are attached, normal enforcement begins.

---

# Part 4: Policy Precedence Tree

LIAS evaluates every packet using a strict precedence hierarchy.

The **first matching rule wins.**

```mermaid
flowchart TD
    Start([Packet Arrives from Device]) --> CheckInfra{"Device tagged 'infrastructure'?"}

    %% 1. Infrastructure Immunity
    CheckInfra -- "YES" --> InfraAllow["EVAL: ALLOW (Immune)"]

    %% 2. Global Toggles
    CheckInfra -- "NO" --> CheckGlobal{"Evaluate 'global_default' policy"}

    CheckGlobal -- "Action == BLOCK" --> GlobalBlock["EVAL: BLOCK (Kill-Switch)"]
    CheckGlobal -- "Action == ALLOW" --> GlobalAllow["EVAL: ALLOW (Global Override)"]

    %% 3. Fallthrough
    CheckGlobal -- "Action == SCHEDULE" --> CheckDevice{"Device-specific policy exists?"}

    CheckDevice -- "YES" --> EvalDevice["Evaluate highest-priority Device Policy"]
    CheckDevice -- "NO" --> CheckTag{"Tag-specific policy exists?"}

    CheckTag -- "YES" --> EvalTag["Evaluate ALL matching Tag Policies\n(Fail-Closed OR: If ANY tag says BLOCK, drop it)"]
    CheckTag -- "NO" --> EvalGlobalSched["Evaluate Global Schedule Bundle"]

    %% Schedule evaluation
    EvalDevice --> SchedCheck{"Action == SCHEDULE ?"}
    EvalTag --> SchedCheck
    EvalGlobalSched --> SchedCheck

    SchedCheck -- "Action == ALLOW/BLOCK" --> FinalAction["EVAL: ALLOW / BLOCK"]

    SchedCheck -- "Action == SCHEDULE" --> EvalBundle["Call schedEval.EvaluateBundle(scheduleIDs)"]

    EvalBundle --> SchedEmpty{"Is scheduleIDs empty?"}

    SchedEmpty -- "YES (Empty)" --> AllowEmpty["EVAL: ALLOW\n(Default Open: No restriction)"]

    SchedEmpty -- "NO" --> SchedExist{"Are schedules valid & conflict-free?"}

    SchedExist -- "Missing or Conflicting" --> FailClosed["EVAL: BLOCK\n(Fail-closed for safety)"]

    SchedExist -- "Valid" --> EvalTime["Evaluate time rules against Current Time"]

    EvalTime --> FinalAction

    %% Styling
    classDef infra fill:#d4edda,stroke:#28a745,stroke-width:2px;
    classDef block fill:#f8d7da,stroke:#dc3545,stroke-width:2px;
    classDef allow fill:#d1ecf1,stroke:#17a2b8,stroke-width:2px;

    class InfraAllow infra;
    class GlobalBlock,FailClosed block;
    class GlobalAllow,AllowEmpty allow;
```

---

# Breakdown of the Precedence Rules

## 1. Infrastructure Immunity (Super-Immutable)

If a device carries the **infrastructure** tag, evaluation immediately returns:

```
ALLOW
```

No global switch, tag policy, device policy, or schedule is evaluated.

Infrastructure devices can never be accidentally disconnected.

Examples include:

- Router
- Firewall
- DNS Server
- DHCP Server
- VPN Gateway
- Switch Management

---

## 2. Global Kill-Switch (BLOCK)

If the Global Policy is set to:

```
BLOCK
```

Every non-infrastructure device is immediately:

```
BLOCKED
```

No additional policy evaluation occurs.

---

## 3. Global Allow Override

If the Global Policy is:

```
ALLOW
```

Every non-infrastructure device is immediately:

```
ALLOWED
```

All schedules and tag/device rules are bypassed.

---

## 4. Global Schedule Mode

If the Global Policy is:

```
SCHEDULE
```

Evaluation proceeds in the following order.

### Device Policy

If a policy exists for the specific PDID:

```
Highest Priority Device Policy
```

is evaluated.

---

### Tag Policy

If no device policy exists:

Evaluate **all matching tag policies**.

Conflict rule:

```
If ANY tag evaluates to BLOCK
→ BLOCK
```

This is a fail-closed OR model.

---

### Global Fallback

If neither device nor tag policies apply:

Evaluate the schedules attached to:

```
global_default
```

---

## 5. Schedule Evaluation

### Empty Schedule Bundle

Policy Action

```
Schedule
```

Attached Schedules

```
None
```

Result

```
ALLOW
```

This prevents lockouts.

---

### Missing or Conflicting Schedules

Examples:

- Deleted schedule still referenced
- Invalid bundle
- Conflicting merged timeline

Result

```
BLOCK
```

The engine fails closed for safety.

---

### Valid Schedule Bundle

If schedules are valid:

1. Merge all schedules.
2. Build a weekly composite timeline.
3. Determine the current active rule.
4. Return either:

```
ALLOW
```

or

```
BLOCK
```
based on the active time window.


