module github.com/user/lias-dis/apps/lias

go 1.23

require (
	github.com/google/nftables v0.3.0
	github.com/user/lias-dis/shared v0.0.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.34.0
)

replace github.com/user/lias-dis/shared => ../../shared
