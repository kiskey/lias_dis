module github.com/user/lias-dis/apps/lias

go 1.23

replace github.com/user/lias-dis/pkg/oui => ../../pkg/oui

replace github.com/user/lias-dis/shared => ../../shared

require (
	github.com/google/nftables v0.2.0
	github.com/user/lias-dis/pkg/oui v0.0.0-00010101000000-000000000000
	github.com/user/lias-dis/shared v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.10.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.32.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	gopkg.in/check.v1 v1.0.0-20161208181325-20d25e280405 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)
