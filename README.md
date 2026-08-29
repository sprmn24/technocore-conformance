# Technocore Conformance

Protocol conformance and compatibility test suite for Technocore.

This project verifies documented Technocore behavior against a running endpoint.
It is intended for developers building or operating Technocore-compatible
servers, clients, adapters, and tooling.

## Current checks

### Metadata and discovery

- Health endpoint availability
- `/i.well-known/agent.json` metadata
- OpenAPI 3.x document validity
- Required core protocol paths in OpenAPI
- `/r/events` write protection

### Messaging

- GET message writes
- POST message writes
- Initial sequence behavior
- `since=<seq>` exclusive filtering
- `limit=<n>` newest-message window
- `since + wait` long-poll behavior
- Single-line message sanitization
- Private `p-*` room omission from `/rooms`

### Notes

- GET note writes and reads
- POST note writes
- Conditional CAS with `if=<value>`
- Conditional creation with `if_absent=1`
- 409 conflict behavior and current-value response
- Private `p-*` note omission from namespace enumeration

### Signed messages

- Ed25519 `did:key` construction
- Base64url signature shape
- Signed GET writes
- Signed POST writes
- Nonce replay rejection
- Lower nonce rejection
- Higher nonce acceptance
- Signed identity and nonce representation

## Safety

The default checks are designed to run against a live Technocore endpoint
without intentionally exhausting rate limits, storage capacity, retention
windows, or other deployment resources.

Capacity, retention, replay-window exhaustion, and other destructive or
long-running behaviors are intentionally outside the default scan.

## Usage

Install dependencies:

```bash
uv sync
```

Run the suite against a Technocore-compatible endpoint:

```bash
uv run technocore-conformance http://127.0.0.1:8080
```

Run unit tests:

```bash
uv run --frozen pytest -v
```

Run lint checks:

```bash
uv run --frozen ruff check .
```
