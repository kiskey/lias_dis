module github.com/user/lias-dis/apps/lias

go 1.23

require (
    github.com/google/nftables v0.3.0
    github.com/prometheus/client_golang v1.19.1
    github.com/user/lias-dis/shared v0.0.0
    gopkg.in/yaml.v3 v3.0.1
    modernc.org/sqlite v1.34.0
)

require (
    github.com/beorn7/perks v1.0.1 // indirect
    github.com/cespare/xxhash/v2 v2.3.0 // indirect
    github.com/dustin/go-humanize v1.0.1 // indirect
    github.com/google/uuid v1.6.0 // indirect
    github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
    github.com/mdlayher/socket v0.5.0 // indirect
    github.com/prometheus/client_model v0.6.1 // indirect
    github.com/prometheus/common v0.55.0 // indirect
    github.com/prometheus/procfs v0.15.1 // indirect
    github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
    golang.org/x/net v0.33.0 // indirect
    golang.org/x/sync v0.6.0 // indirect
    golang.org/x/sys v0.28.0 // indirect
    modernc.org/libc v1.55.3 // indirect
    modernc.org/mathutil v1.6.0 // indirect
    modernc.org/memory v1.8.0 // indirect
)

replace github.com/user/lias-dis/shared => ../../shared
