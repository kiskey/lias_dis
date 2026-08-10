# DIS duplicate-PDID fix patch scripts

Ready-to-run local patch scripts for `kiskey/lias_dis`, branch `enhancement2.0`.

## Recommended usage

```bash
git clone https://github.com/kiskey/lias_dis.git
cd lias_dis
git checkout enhancement2.0
git status --short

unzip dis_patch_scripts_ready_to_run.zip
chmod +x dis_patch_scripts/*.patch
./dis_patch_scripts/run_all_dis_batches.patch "$PWD"
```

## Manual order

```bash
./01_dis_acceptance_tests.patch /path/to/lias_dis
./02_dis_reconcile_zero_mac_orphans.patch /path/to/lias_dis
./03_dis_reconcile_tests.patch /path/to/lias_dis
./04_dis_hydration_guard.patch /path/to/lias_dis
./05_dis_full_acceptance.patch /path/to/lias_dis
```

## Batch summary

1. `01_dis_acceptance_tests.patch`
   - Adds acceptance coverage for dormant historical MAC ownership.

2. `02_dis_reconcile_zero_mac_orphans.patch`
   - Adds `Storage.ReconcileZeroMACOrphanDuplicates()`.
   - Runs it at DIS SQLite startup.
   - Auto-repairs only safe zero-MAC orphan duplicates where `device_macs` already has the authoritative owner.
   - Leaves ambiguous/verified conflict records untouched.

3. `03_dis_reconcile_tests.patch`
   - Adds tests for safe zero-MAC orphan reconciliation.
   - Adds tests proving verified-alias ambiguous orphans are not auto-merged.

4. `04_dis_hydration_guard.patch`
   - Adds a `LoadHydrate` safety net so corrupted `devices.current_mac` rows cannot hydrate as duplicate visible devices when `device_macs` says the MAC belongs to another PDID.

5. `05_dis_full_acceptance.patch`
   - Runs focused DIS suites and `go test ./...`.

## Contract guarantee

These scripts do not add API fields and do not change `shared/models.Device`. They preserve existing REST, SSE, Android, dashboard, and LIAS JSON contracts.
