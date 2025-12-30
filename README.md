# JARVIS PDP

First-party OSS reference implementation of the **ARP Policy Decision Point (PDP)** service.

This reference implementation uses only the SDK packages:
`arp-standard-server`, `arp-standard-model`, and `arp-standard-client`, plus `arp-policy` and `arp-auth`.

It is designed to be a thin adapter to your real governance system (rules, OPA, internal policy services), while keeping a stable, spec-aligned request/response schema.

Implements: ARP Standard `spec/v1` PDP API (contract: `ARP_Standard/spec/v1/openapi/pdp.openapi.yaml`).

## Requirements

- Python >= 3.11

## Install

```bash
python3 -m pip install -e .
```

## Local configuration (optional)

For local dev convenience, copy the example env file:

```bash
cp .env.example .env.local
```

`src/scripts/dev_server.sh` auto-loads `.env.local` (or `.env`).

## Run

- PDP listens on `http://127.0.0.1:8086` by default.

```bash
python3 -m pip install -e .
python3 -m jarvis_pdp
```

> [!TIP]
> Use `bash src/scripts/dev_server.sh --host ... --port ... --reload` for dev convenience.

## Using this repo

To build your own PDP, fork this repository and replace the decision logic while preserving request/response semantics.

If all you need is to change policy behavior, edit:
- `src/jarvis_pdp/service.py`

### Default behavior

- Deny-by-default when no profile or policy file is configured.
- `JARVIS_POLICY_PROFILE=dev-allow` enables allow-all behavior for local dev.
- `JARVIS_POLICY_PATH` loads an `arp-policy` JSON policy file.
- When a policy file is configured and a request includes `node_type_ref`, PDP fetches the `NodeType` from Node Registry
  and enriches the policy context (so callers do not need to embed NodeType metadata in the request).

### Example policy: first-party atomic only

This repo includes an example `arp-policy` file that allows:
- composite nodes (e.g. `jarvis.composite.planner.general`)
- atomic nodes only when `jarvis.trust_tier == "first_party"`

See: `src/scripts/policy.first_party_atomic_only.json`

To use it:

```bash
export JARVIS_POLICY_PATH=src/scripts/policy.first_party_atomic_only.json
```

## Quick health check

```bash
curl http://127.0.0.1:8086/v1/health
```

## Configuration

CLI flags:
- `--host` (default `127.0.0.1`)
- `--port` (default `8086`)
- `--reload` (dev only)

Environment variables (Node Registry hydration):
- `JARVIS_NODE_REGISTRY_URL` (enables NodeType metadata hydration for node-type policy decisions)
- `JARVIS_NODE_REGISTRY_AUDIENCE` (default `arp-jarvis-noderegistry`)
- Outbound STS credentials (required when `JARVIS_NODE_REGISTRY_URL` is set):
  - `ARP_AUTH_CLIENT_ID`
  - `ARP_AUTH_CLIENT_SECRET`
  - `ARP_AUTH_TOKEN_ENDPOINT` (or `ARP_AUTH_ISSUER` + discovery)

## Validate conformance (`arp-conformance`)

```bash
python3 -m pip install arp-conformance
arp-conformance check pdp --url http://127.0.0.1:8086 --tier smoke
arp-conformance check pdp --url http://127.0.0.1:8086 --tier surface
```

## Helper scripts

- `src/scripts/dev_server.sh`: run the server (flags: `--host`, `--port`, `--reload`).
- `src/scripts/send_request.py`: send a policy decision request from a JSON file.

  ```bash
  python3 src/scripts/send_request.py --request src/scripts/request.json
  ```

## Authentication

Auth is enabled by default (JWT). To disable for local dev, set `ARP_AUTH_PROFILE=dev-insecure`.

To enable local Keycloak defaults, set:
- `ARP_AUTH_PROFILE=dev-secure-keycloak`
- `ARP_AUTH_AUDIENCE=arp-pdp`
- `ARP_AUTH_ISSUER=http://localhost:8080/realms/arp-dev`

## Upgrading

When upgrading to a new ARP Standard SDK release, bump pinned versions in `pyproject.toml` (`arp-standard-*==...`) and re-run conformance.
