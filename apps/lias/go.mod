// File:    apps/lias/go.mod
// Version: 1.0
module github.com/user/lias-dis/apps/lias

go 1.23

require (
    github.com/google/nftables v0.2.0
    github.com/user/lias-dis/shared v1.0.0
    gopkg.in/yaml.v3 v3.0.1
)

replace github.com/user/lias-dis/shared => ../../shared
