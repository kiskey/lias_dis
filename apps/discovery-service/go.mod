module github.com/user/lias-dis/apps/discovery-service

go 1.23

replace github.com/user/lias-dis/pkg/oui => ../../pkg/oui

replace github.com/user/lias-dis/shared => ../../shared

require (
	github.com/user/lias-dis/pkg/oui v0.0.0-00010101000000-000000000000
	github.com/user/lias-dis/shared v0.0.0-00010101000000-000000000000
	github.com/vishvananda/netlink v1.3.0
	golang.org/x/sys v0.10.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/vishvananda/netns v0.0.4 // indirect
	gopkg.in/check.v1 v1.0.0-20161208181325-20d25e280405 // indirect
)
