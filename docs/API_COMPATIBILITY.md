# DIS–LIAS API v1 compatibility contract

The public DIS contract is the authenticated REST and SSE surface under
`/api/v1`. The public device identity key is always `pdid`.
`device_id` inside a Device record is an opaque internal identifier and must
not be used for LIAS policy keys.

## Capability discovery

`GET /api/v1/capabilities` returns a small, cacheable response:

    {
      "api_version": "v1",
      "schema_version": 1,
      "min_client_api_version": "v1",
      "public_device_key": "pdid",
      "response_compatibility": "additive",
      "features": [
        "authenticated_identity",
        "device_inventory",
        "identity_bindings",
        "identity_candidates",
        "identity_split",
        "sse_events",
        "sse_replay"
      ]
    }

Clients must test for a feature string before depending on an optional
endpoint. Unknown feature strings must be ignored. This endpoint is computed
from constants, has no storage access, and is cacheable for five minutes.

## Stability rules

Within `/api/v1`:

- Existing routes, methods, status meanings, JSON field names, and enum values
  are not removed or renamed.
- Response objects may gain optional fields. Clients must ignore fields they do
  not understand.
- Request objects are strict and may reject unknown fields. New request
  semantics use an optional field, a new endpoint, or a new API namespace.
- New SSE event types may be added. Unknown types are safe to relay or ignore
  but never cause policy enforcement.
- Existing SSE framing remains `event`, `id`, and JSON `data` lines.
- Device-scoped SSE payloads use `pdid`. The Go `Event.DeviceID` field is a
  deprecated compatibility alias that also carries the PDID.
- A breaking change requires `/api/v2`; it is not represented by increasing
  `schema_version` inside v1.

## Compatibility matrix

| Pairing | Expected behavior |
| --- | --- |
| Older LIAS with current DIS | Existing v1 behavior works; additive fields/events are ignored |
| Current LIAS with older DIS | Existing inventory and SSE behavior works; unsupported features are absent |
| Current LIAS with current DIS | Capabilities advertise optional identity and SSE features |

## Executable gates

CI verifies:

- the golden v1 capability document;
- current Device responses decoded by a legacy v1 client structure;
- future unknown fields decoded by the current LIAS structure;
- unchanged SSE v1 framing and the legacy `device_id` alias;
- explicit PDID resolution for current, legacy, and reidentification payloads;
- unknown/global events relay without cache, policy, network, or storage work;
- the authenticated capability route and existing device-list wrapper.

These tests protect wire compatibility in addition to the shared Go types.

## Resource behavior

Contract negotiation adds no background work, goroutines, database tables,
SQLite writes, filesystem access, or polling. The capability response is
generated only when requested. LIAS SSE parsing starts with a 4 KiB buffer,
grows only when required, and rejects an individual event above 1 MiB.
