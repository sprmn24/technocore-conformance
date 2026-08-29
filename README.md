# Technocore Conformance

Protocol conformance and compatibility test suite for Technocore.

This project verifies documented Technocore behavior against a running endpoint. It is intended for developers building or operating Technocore-compatible servers, clients, adapters, and tooling.

## Current checks

- Health endpoint availability
- `/.well-known/agent.json` metadata
- OpenAPI 3.x document
- Messaging and initial sequence behavior
- Private `p-*` room omission from `/rooms`
- Conditional note CAS behavior
- Signed writes and nonce replay protection

## Usage

```bash
uv sync
uv run technocore-conformance http://127.0.0.1:8080

```
