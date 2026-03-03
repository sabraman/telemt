# Telemt Control API

## Purpose
This document specifies the control-plane HTTP API used for:
- runtime statistics access,
- user management,
- safe configuration mutations.

The data-plane (MTProto proxy traffic) is out of scope.

## Design Principles
1. Keep data-plane isolated.
The API must not affect MTProto hot paths.

2. Keep configuration authoritative.
`config.toml` is the single source of truth for managed entities.

3. Make writes safe.
All config mutations are validated and persisted atomically.

4. Be explicit about concurrency.
Mutating endpoints support optimistic concurrency through revision matching.

5. Prefer fail-fast contract errors.
Input validation errors are returned with machine-readable error codes.

## Runtime and Configuration
Control API runtime is configured under `[server.api]`.

Parameters:
- `enabled: bool`
- `listen: "IP:PORT"`
- `whitelist: [CIDR, ...]`
- `auth_header: string` (exact match against `Authorization` header; empty disables header auth)
- `request_body_limit_bytes: usize`
- `read_only: bool`

Backward compatibility:
- `server.admin_api` is accepted as an alias while `server.api` is canonical.

Operational note:
- Changes in `server.api` require process restart to take effect.

## Protocol Contract
- Transport: HTTP/1.1
- Payload format: JSON (`application/json; charset=utf-8`)
- API prefix: `/v1`

### Success Envelope
```json
{
  "ok": true,
  "data": {},
  "revision": "sha256-of-config"
}
```

### Error Envelope
```json
{
  "ok": false,
  "error": {
    "code": "machine_code",
    "message": "human-readable text"
  },
  "request_id": 1
}
```

### Revision / Concurrency Contract
- Mutating operations MAY include `If-Match: <revision>`.
- If provided and stale, API returns `409 revision_conflict`.
- Revision is a SHA-256 hash of current config file content.

## Endpoints

### Read endpoints
- `GET /v1/health`
- `GET /v1/stats/summary`
- `GET /v1/stats/me-writers`
- `GET /v1/stats/dcs`
- `GET /v1/stats/users`
- `GET /v1/users`
- `GET /v1/users/{username}`

### Mutating endpoints
- `POST /v1/users`
- `PATCH /v1/users/{username}`
- `POST /v1/users/{username}/rotate-secret`
- `DELETE /v1/users/{username}`

## Entity Contract: User
Managed user fields:
- `username`
- `secret` (32 hex chars)
- `user_ad_tag` (32 hex chars, optional)
- `max_tcp_conns` (optional)
- `expiration_rfc3339` (optional)
- `data_quota_bytes` (optional)
- `max_unique_ips` (optional)

Derived runtime fields (read-only in API responses):
- `current_connections`
- `active_unique_ips`
- `total_octets`

## Transport Status Endpoints
### `GET /v1/stats/me-writers`
Returns current Middle-End writer status and aggregated coverage/availability summary.

Top-level fields:
- `middle_proxy_enabled`
- `generated_at_epoch_secs`
- `summary`
- `writers`

Summary fields:
- `configured_dc_groups`
- `configured_endpoints`
- `available_endpoints`
- `available_pct`
- `required_writers`
- `alive_writers`
- `coverage_pct`

Writer fields:
- `writer_id`
- `dc`
- `endpoint` (`ip:port`)
- `generation`
- `state` (`warm|active|draining`)
- `draining`
- `degraded`
- `bound_clients`
- `idle_for_secs`
- `rtt_ema_ms`

### `GET /v1/stats/dcs`
Returns per-DC status aggregated from current ME pool.

Top-level fields:
- `middle_proxy_enabled`
- `generated_at_epoch_secs`
- `dcs`

DC row fields:
- `dc`
- `endpoints` (`ip:port[]`)
- `available_endpoints`
- `available_pct`
- `required_writers`
- `alive_writers`
- `coverage_pct`
- `rtt_ms`
- `load`

Metrics formulas:
- `available_pct = available_endpoints / configured_endpoints * 100`
- `coverage_pct = alive_writers / required_writers * 100`
- `required_writers` uses the runtime writer floor policy for each DC group.
- `load` is the number of active client sessions currently bound to that DC.

## Validation Rules
- `username` must match `[A-Za-z0-9_.-]`, length `1..64`.
- `secret` must be exactly 32 hexadecimal characters.
- `user_ad_tag` must be exactly 32 hexadecimal characters.
- Request body size must not exceed `request_body_limit_bytes`.

## Security Model
1. Network perimeter.
Access is limited by CIDR whitelist.

2. Optional application header auth.
If `auth_header` is configured, `Authorization` must match exactly.

3. Read-only mode.
If `read_only = true`, mutating endpoints are rejected with `403`.

## Mutation Approach
1. Acquire mutation lock.
2. Load config from disk.
3. Validate optional `If-Match` revision.
4. Apply in-memory mutation.
5. Run config validation.
6. Persist via atomic write (`tmp + fsync + rename`).
7. Return updated revision.

Runtime apply path:
- Existing config watcher picks up persisted changes and applies them through the standard hot-reload path.

## Known Limitations
1. Built-in TLS/mTLS is not provided by this API server.
Use loopback bind plus reverse proxy for external exposure.

2. No pagination/filtering for user list in current version.

3. `PATCH` updates present fields only.
Field deletion semantics are not implemented as explicit nullable operations.

4. Config comments and manual formatting are not preserved after mutation.
Config is serialized from structured state.

5. API configuration itself (`server.api`) is not hot-applied.
Restart is required.

6. Atomic file replacement can conflict with external editors/tools writing the same config concurrently.
Use revision checks to reduce race impact.
