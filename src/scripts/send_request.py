#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_REQUEST_PATH = Path(__file__).with_name("request.json")


def _request(method: str, url: str, body: dict | None, headers: dict[str, str]) -> object:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req) as resp:
            payload = resp.read().decode("utf-8")
    except HTTPError as exc:
        payload = exc.read().decode("utf-8")
        raise SystemExit(f"HTTP {exc.code} {exc.reason}: {payload}") from exc
    except URLError as exc:
        raise SystemExit(f"Request failed: {exc.reason}") from exc
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload


def _load_request(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit("Request JSON must be an object.")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a policy decision request from a JSON file.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="8086")
    parser.add_argument("--request", default=str(DEFAULT_REQUEST_PATH), help="Path to a JSON request body.")
    args = parser.parse_args()

    request_path = Path(args.request)
    body = _load_request(request_path)

    base_url = f"http://{args.host}:{args.port}/v1"
    headers = {"Content-Type": "application/json"}

    result = _request("POST", f"{base_url}/policy:decide", body, headers)
    print(json.dumps({"result": result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

