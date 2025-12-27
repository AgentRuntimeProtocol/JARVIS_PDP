# ARP Template PDP

Use this repo as a starting point for building an **ARP compliant Policy Decision Point (PDP)** service.

This minimal template implements the PDP API using only the SDK packages:
`arp-standard-server`, `arp-standard-model`, and `arp-standard-client`.

It is designed to be a thin adapter to your real governance system (rules, OPA, internal policy services), while keeping a stable, spec-aligned request/response schema.

Implements: ARP Standard `spec/v1` PDP API (contract: `ARP_Standard/spec/v1/openapi/pdp.openapi.yaml`).

## Requirements

- Python >= 3.10

## Install

```bash
python3 -m pip install -e .
```

## Local configuration (optional)

For local dev convenience, copy the template env file:

```bash
cp .env.example .env.local
```

`src/scripts/dev_server.sh` auto-loads `.env.local` (or `.env`).

## Run

- PDP listens on `http://127.0.0.1:8086` by default.

```bash
python3 -m pip install -e '.[run]'
python3 -m arp_template_pdp
```

> [!TIP]
> Use `bash src/scripts/dev_server.sh --host ... --port ... --reload` for dev convenience.

## Using this repo

To build your own PDP, fork this repository and replace the decision logic while preserving request/response semantics.

If all you need is to change policy behavior, edit:
- `src/arp_template_pdp/service.py`

### Default behavior

- Policy mode defaults to `allow_all`.
- Optional `file` mode supports `ARP_POLICY_PATH` with a simple JSON format.

#### Policy file format (`file` mode)

Set:
- `ARP_POLICY_MODE=file`
- `ARP_POLICY_PATH=/path/to/policy.json`

Example `policy.json`:

```json
{
  "deny_actions": ["run.start"],
  "require_approval_actions": ["run.cancel"]
}
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

For out-of-the-box usability, this template defaults to auth-disabled unless you set `ARP_AUTH_MODE` or `ARP_AUTH_PROFILE`.

To enable JWT auth, set either:
- `ARP_AUTH_PROFILE=dev-secure-keycloak` + `ARP_AUTH_SERVICE_ID=<audience>`
- or `ARP_AUTH_MODE=required` with `ARP_AUTH_ISSUER` and `ARP_AUTH_AUDIENCE`

## Upgrading

When upgrading to a new ARP Standard SDK release, bump pinned versions in `pyproject.toml` (`arp-standard-*==...`) and re-run conformance.
