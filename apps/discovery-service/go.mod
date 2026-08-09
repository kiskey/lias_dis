module github.com/user/lias-dis/apps/discovery-service

go 1.23.0

replace github.com/user/lias-dis/pkg/oui => ../../pkg/oui

replace github.com/user/lias-dis/shared => ../../shared

require (
	github.com/user/lias-dis/pkg/oui v0.0.0-00010101000000-000000000000
	github.com/user/lias-dis/shared v0.0.0-00010101000000-000000000000
	github.com/vishvananda/netlink v1.3.0
	golang.org/x/sys v0.34.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.38.2
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/endobit/oui v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	gopkg.in/check.v1 v1.0.0-20161208181325-20d25e280405 // indirect
	modernc.org/libc v1.66.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
