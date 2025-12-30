from __future__ import annotations

import asyncio
import os

from arp_auth import AuthClient, AuthError
from arp_standard_server import ArpServerError


def auth_client_from_env_optional() -> AuthClient | None:
    """
    Build an `arp-auth` client for outbound calls (token exchange) if configured.

    This is optional so the PDP can still run in a minimal "deny-by-default" posture
    without any outbound dependencies configured.
    """
    client_id = (os.environ.get("ARP_AUTH_CLIENT_ID") or "").strip()
    client_secret = (os.environ.get("ARP_AUTH_CLIENT_SECRET") or "").strip()
    if not client_id and not client_secret:
        return None
    if not client_id or not client_secret:
        raise RuntimeError("ARP_AUTH_CLIENT_ID and ARP_AUTH_CLIENT_SECRET are required for outbound auth.")
    try:
        return AuthClient.from_env()
    except AuthError as exc:
        raise RuntimeError(f"Invalid ARP_AUTH_* token exchange config: {exc}") from exc


async def client_credentials_token(
    auth_client: AuthClient,
    *,
    audience: str | None,
    scope: str | None,
    service_label: str,
) -> str:
    try:
        token = await asyncio.to_thread(
            auth_client.client_credentials,
            audience=audience,
            scope=scope,
        )
    except Exception as exc:
        raise ArpServerError(
            code="token_request_failed",
            message=f"{service_label} token request failed",
            status_code=getattr(exc, "status_code", None) or 502,
            details=None,
        ) from exc
    return token.access_token
