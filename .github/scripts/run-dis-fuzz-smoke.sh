#!/usr/bin/env bash
set -euo pipefail

FUZZ_TIME="${DIS_FUZZ_TIME:-3s}"
TARGETS=(
  FuzzParseNodeStatusResponse
  FuzzParseNodeStatusRDATA
  FuzzParseSSDPMessage
  FuzzParseSSDPDescriptor
  FuzzParseDNSMasqLeases
  FuzzParseKeaLeases
  FuzzParseAvahiBrowseLine
  FuzzParsePiholeClients
  FuzzParseNmapXML
)

for target in "${TARGETS[@]}"; do
  printf 'Fuzz smoke: %s (%s)\n' "$target" "$FUZZ_TIME"
  go test ./apps/discovery-service/internal/discovery \
    -run='^$' -fuzz="^${target}$" -fuzztime="$FUZZ_TIME"
done
