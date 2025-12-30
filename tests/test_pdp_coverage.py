from __future__ import annotations

import asyncio
import os
import sys
import importlib
from pathlib import Path
from typing import Any, Callable

import pytest
from arp_standard_client.errors import ArpApiError
from arp_standard_model import (
    Extensions,
    NodeKind,
    NodeType,
    NodeTypeRef,
    PdpDecidePolicyRequest,
    PdpHealthRequest,
    PdpVersionRequest,
    PolicyDecisionOutcome,
    PolicyDecisionRequest,
    RunContext,
)
from arp_standard_server import ArpServerError

from jarvis_pdp import __main__ as pdp_main
from jarvis_pdp import auth as pdp_auth
from jarvis_pdp import utils as pdp_utils
from jarvis_pdp.clients.node_registry_client import NodeRegistryGatewayClient
from jarvis_pdp.service import PdpService


def test_health_and_version() -> None:
    service = PdpService()

    health = asyncio.run(service.health(PdpHealthRequest()))
    assert health.status.value == "ok"

    version = asyncio.run(service.version(PdpVersionRequest()))
    assert version.service_name
    assert version.service_version


def test_utils_auth_settings_env_or_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # No ARP_AUTH_* env: fall back to "required" with the dev Keycloak issuer.
    for key in list(os.environ):
        if key.startswith("ARP_AUTH_"):
            monkeypatch.delenv(key, raising=False)

    settings = pdp_utils.auth_settings_from_env_or_dev_insecure()
    assert settings.mode == "required"
    assert settings.issuer == pdp_utils.DEFAULT_DEV_KEYCLOAK_ISSUER

    # Any ARP_AUTH_* env triggers AuthSettings.from_env; dev-insecure disables auth.
    monkeypatch.setenv("ARP_AUTH_PROFILE", "dev-insecure")
    settings = pdp_utils.auth_settings_from_env_or_dev_insecure()
    assert settings.mode == "disabled"


def test_auth_client_from_env_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARP_AUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("ARP_AUTH_CLIENT_SECRET", raising=False)

    assert pdp_auth.auth_client_from_env_optional() is None

    monkeypatch.setenv("ARP_AUTH_CLIENT_ID", "pdp")
    with pytest.raises(RuntimeError, match="ARP_AUTH_CLIENT_ID and ARP_AUTH_CLIENT_SECRET"):
        pdp_auth.auth_client_from_env_optional()


def test_client_credentials_token_success_and_failure() -> None:
    class _Token:
        def __init__(self, access_token: str) -> None:
            self.access_token = access_token

    class _AuthClientStub:
        def __init__(self, behavior: Callable[[], Any]) -> None:
            self._behavior = behavior

        def client_credentials(self, *, audience: str | None, scope: str | None) -> Any:
            _ = audience, scope
            return self._behavior()

    token = asyncio.run(
        pdp_auth.client_credentials_token(
            _AuthClientStub(lambda: _Token("abc")),  # type: ignore[arg-type]
            audience=None,
            scope=None,
            service_label="Node Registry",
        )
    )
    assert token == "abc"

    with pytest.raises(ArpServerError, match="Node Registry token request failed"):
        asyncio.run(
            pdp_auth.client_credentials_token(
                _AuthClientStub(lambda: (_ for _ in ()).throw(ValueError("boom"))),  # type: ignore[arg-type]
                audience=None,
                scope=None,
                service_label="Node Registry",
            )
        )


def test_node_registry_gateway_client_error_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    class _StubClient:
        def __init__(self, *, exc: Exception) -> None:
            self._exc = exc

        def get_node_type(self, request: Any) -> Any:
            _ = request
            raise self._exc

    gateway = NodeRegistryGatewayClient(
        base_url="http://node-registry",
        auth_client=object(),  # type: ignore[arg-type]
    )

    async def _client_for_api_error() -> Any:
        return _StubClient(exc=ArpApiError(code="node_type_not_found", message="nope", status_code=404))

    monkeypatch.setattr(gateway, "_client_for", _client_for_api_error)
    with pytest.raises(ArpServerError) as exc_info:
        asyncio.run(gateway.get_node_type("x", "1.0.0"))
    assert exc_info.value.code == "node_type_not_found"
    assert exc_info.value.status_code == 404

    async def _client_for_generic_error() -> Any:
        return _StubClient(exc=RuntimeError("boom"))

    monkeypatch.setattr(gateway, "_client_for", _client_for_generic_error)
    with pytest.raises(ArpServerError) as exc_info:
        asyncio.run(gateway.get_node_type("x", "1.0.0"))
    assert exc_info.value.code == "node_registry_unavailable"


def _import_app_dev_insecure(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ARP_AUTH_PROFILE", "dev-insecure")
    monkeypatch.delenv("JARVIS_NODE_REGISTRY_URL", raising=False)
    import jarvis_pdp.app as pdp_app

    return importlib.reload(pdp_app)


def test_app_create_app_requires_outbound_auth_when_node_registry_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pdp_app = _import_app_dev_insecure(monkeypatch)
    monkeypatch.setenv("JARVIS_NODE_REGISTRY_URL", "http://127.0.0.1:8085")
    monkeypatch.delenv("ARP_AUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("ARP_AUTH_CLIENT_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="ARP_AUTH_CLIENT_ID and ARP_AUTH_CLIENT_SECRET"):
        pdp_app.create_app()


def test_app_create_app_happy_path_with_node_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    pdp_app = _import_app_dev_insecure(monkeypatch)
    captured: dict[str, Any] = {}

    class _DummyGatewayClient:
        def __init__(self, *, base_url: str, auth_client: Any, audience: str | None) -> None:
            captured["base_url"] = base_url
            captured["audience"] = audience

    class _DummyPdpService:
        def __init__(self, *, node_registry: Any = None) -> None:
            captured["node_registry"] = node_registry

        def create_app(self, *, title: str, auth_settings: Any) -> Any:
            captured["title"] = title
            captured["auth_settings"] = auth_settings
            return {"ok": True}

    monkeypatch.setenv("JARVIS_NODE_REGISTRY_URL", "http://127.0.0.1:8085")
    monkeypatch.setenv("JARVIS_NODE_REGISTRY_AUDIENCE", "arp-jarvis-noderegistry")
    monkeypatch.setattr(pdp_app, "NodeRegistryGatewayClient", _DummyGatewayClient)
    monkeypatch.setattr(pdp_app, "PdpService", _DummyPdpService)
    monkeypatch.setattr(pdp_app, "auth_client_from_env_optional", lambda: object())

    result = pdp_app.create_app()
    assert result == {"ok": True}
    assert captured["base_url"] == "http://127.0.0.1:8085"
    assert captured["audience"] == "arp-jarvis-noderegistry"


def test_service_file_policy_invalid_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    bad_policy = tmp_path / "bad.json"
    bad_policy.write_text("{not json", encoding="utf-8")
    monkeypatch.delenv("JARVIS_POLICY_PROFILE", raising=False)
    monkeypatch.setenv("JARVIS_POLICY_PATH", str(bad_policy))

    service = PdpService()
    request = PdpDecidePolicyRequest(body=PolicyDecisionRequest(action="node.run.execute"))
    result = asyncio.run(service.decide_policy(request))
    assert result.decision == PolicyDecisionOutcome.deny
    assert result.reason_code == "invalid_policy"


def test_service_legacy_policy_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JARVIS_POLICY_PROFILE", raising=False)
    monkeypatch.delenv("JARVIS_POLICY_PATH", raising=False)
    monkeypatch.delenv("ARP_POLICY_PATH", raising=False)

    service = PdpService()
    request = PdpDecidePolicyRequest(body=PolicyDecisionRequest(action="node.run.execute"))

    monkeypatch.setenv("ARP_POLICY_MODE", "allow_all")
    result = asyncio.run(service.decide_policy(request))
    assert result.decision == PolicyDecisionOutcome.allow

    monkeypatch.setenv("ARP_POLICY_MODE", "file")
    result = asyncio.run(service.decide_policy(request))
    assert result.decision == PolicyDecisionOutcome.deny
    assert result.reason_code == "missing_policy_path"


def test_service_build_context_run_context_branch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "allow.json"
    policy.write_text(
        '{\"Version\":\"0.1.0\",\"Statement\":[{\"Sid\":\"AllowAll\",\"Effect\":\"Allow\",\"Action\":[\"node.run.execute\"],\"Resource\":\"run:*\"}]}',
        encoding="utf-8",
    )
    monkeypatch.delenv("JARVIS_POLICY_PROFILE", raising=False)
    monkeypatch.setenv("JARVIS_POLICY_PATH", str(policy))

    service = PdpService()
    request = PdpDecidePolicyRequest(
        body=PolicyDecisionRequest(
            action="node.run.execute",
            run_id="run_1",
            run_context=RunContext(),
            context={"resource": "run:*"},
        )
    )
    result = asyncio.run(service.decide_policy(request))
    assert result.decision == PolicyDecisionOutcome.allow


def test_main_invokes_uvicorn_reload_and_non_reload(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, str, int, bool]] = []

    def _fake_run(app: Any, *, host: str, port: int, reload: bool) -> None:
        calls.append((app, host, port, reload))

    monkeypatch.setattr(pdp_main.uvicorn, "run", _fake_run)

    # Reload path: uses "jarvis_pdp.app:app" import string.
    monkeypatch.setattr(sys, "argv", ["arp-jarvis-pdp", "--host", "0.0.0.0", "--port", "1234", "--reload"])
    pdp_main.main()
    assert calls[-1] == ("jarvis_pdp.app:app", "0.0.0.0", 1234, True)

    # Non-reload path: builds the app object and passes it to uvicorn.
    pdp_app = _import_app_dev_insecure(monkeypatch)
    sentinel = object()
    monkeypatch.setattr(pdp_app, "create_app", lambda: sentinel)
    monkeypatch.setattr(sys, "argv", ["arp-jarvis-pdp", "--host", "0.0.0.0", "--port", "2345"])
    pdp_main.main()
    assert calls[-1] == (sentinel, "0.0.0.0", 2345, False)
