# DIS validation and resource budgets

These are regression ceilings for a small LAN deployment. They are not claims
that passive observations can prove identity across arbitrary private-MAC
changes.

## Required CI gates

```bash
go test -count=1 ./shared/... ./apps/discovery-service/... ./apps/lias/...
go vet ./shared/... ./apps/discovery-service/... ./apps/lias/...
CGO_ENABLED=1 go test -race -count=1 \
  ./apps/discovery-service/internal/api \
  ./apps/discovery-service/internal/config \
  ./apps/discovery-service/internal/correlation \
  ./apps/discovery-service/internal/discovery \
  ./apps/discovery-service/internal/identity \
  ./apps/discovery-service/internal/inventory \
  ./apps/discovery-service/internal/storage
bash .github/scripts/run-dis-fuzz-smoke.sh
```

The CI workflow also performs CGO-free Linux builds for both DIS and LIAS on
AMD64 and ARM64 and fails if testing or building modifies the repository.

## Regression budgets

| Measurement | Budget |
| --- | ---: |
| Idle CPU at 50 devices | `<1%` of one core |
| Resident memory | `50–75 MiB` target, `75 MiB` heap-growth ceiling in soak |
| Stable heartbeat persistence | At most one admission per device per 5 minutes |
| Dirty-device churn persistence | At most one batch transaction per 5-second flush |
| Enrichment concurrency | 2 workers by default; maximum configuration 8 |
| Enrichment queue | 128 PDIDs by default; maximum configuration 4096 |
| Nmap concurrency | 1 process |
| Nmap packet rate | 50 packets/second by default |
| Presence processing p95 | `<2s` excluding protocol/network timeout |
| Offline transition | 2–5 minutes; current positive-evidence horizon is 3 minutes |
| Parser fuzzing | 0 crashes |
| Race detector | 0 reports |
| Goroutine/cache growth | No growth proportional to repeated events |

## Benchmarks

```bash
go test -run='^$' -bench=. -benchmem \
  ./apps/discovery-service/internal/identity \
  ./apps/discovery-service/internal/correlation
```

Record results together with CPU model, Go version, commit SHA, device count,
enabled providers, and configuration. Do not compare benchmark numbers across
different hardware as if they were calibration measurements.

## 72-hour soak

The soak is intentionally opt-in and skipped by ordinary CI:

```bash
DIS_RUN_SOAK=1 DIS_SOAK_DURATION=72h \
  go test -v -run '^TestDISSoak$' -timeout 73h \
  ./apps/discovery-service/internal/correlation
```

For a shorter preflight, `DIS_SOAK_DURATION` may be set to any duration of at
least one minute. The test drives 200 devices, samples heap and goroutines, and
fails on unbounded cache population, more than 16 additional goroutines, or
more than 75 MiB of heap growth.

For a production soak, also capture process RSS/CPU and SQLite database/WAL
sizes externally at one-minute intervals. The Go heap alone does not include
all mapped memory or operating-system page cache.

## Identity correctness contract

- Exact known MAC aliases preserve the immutable public PDID across IP changes.
- Authenticated MDM/controller/companion credentials may attach a new private
  MAC to an existing PDID.
- Revoking that credential stops future attachment.
- Passive hostname, IP, service, SSDP, TLS, Nmap, DHCP, and vendor evidence may
  create an explainable candidate but always has `AutoMerge=false`.
- Simultaneous old/new presence is conflict evidence.
- Administrator confirmation and split operations remain reversible.
