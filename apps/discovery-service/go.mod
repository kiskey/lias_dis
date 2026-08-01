// File:    apps/discovery-service/go.mod
// Version: 1.0
module github.com/user/lias-dis/apps/discovery-service

go 1.23

require (
    github.com/user/lias-dis/shared v1.0.0
    github.com/vishvananda/netlink v1.3.0
    gopkg.in/yaml.v3 v3.0.1
)

replace github.com/user/lias-dis/shared => ../../shared
