from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from arp_standard_model import (
    Extensions,
    NodeKind,
    NodeType,
    NodeTypeRef,
    PdpDecidePolicyRequest,
    PolicyDecisionOutcome,
    PolicyDecisionRequest,
)
from jarvis_pdp.service import PdpService


def test_default_denies_without_profile() -> None:
    service = PdpService()
    request = PdpDecidePolicyRequest(body=PolicyDecisionRequest(action="run.start"))

    result = asyncio.run(service.decide_policy(request))

    assert result.decision == PolicyDecisionOutcome.deny


def _sample_policy_path() -> str:
    return str(
        Path(__file__).resolve().parents[1] / "src" / "scripts" / "policy.first_party_atomic_only.json"
    )


class _DummyNodeRegistry:
    def __init__(self, node_type: NodeType) -> None:
        self._node_type = node_type
        self.calls: list[tuple[str, str | None]] = []

    async def get_node_type(self, node_type_id: str, version: str | None = None) -> NodeType:
        self.calls.append((node_type_id, version))
        return self._node_type


def _pdp_request_for_node(*, node_type_id: str, version: str = "0.3.7") -> PdpDecidePolicyRequest:
    return PdpDecidePolicyRequest(
        body=PolicyDecisionRequest(
            action="node.run.execute",
            run_id="run_123",
            node_run_id="node_run_123",
            node_type_ref=NodeTypeRef(node_type_id=node_type_id, version=version),
        )
    )


def test_node_type_policy_requires_node_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JARVIS_POLICY_PROFILE", raising=False)
    monkeypatch.setenv("JARVIS_POLICY_PATH", _sample_policy_path())

    service = PdpService(node_registry=None)
    request = _pdp_request_for_node(node_type_id="jarvis.web.fetch")

    result = asyncio.run(service.decide_policy(request))

    assert result.decision == PolicyDecisionOutcome.deny
    assert result.reason_code == "node_registry_unconfigured"


@pytest.mark.parametrize(
    ("kind", "trust_tier", "expected_outcome", "expected_sid"),
    [
        ("atomic", "first_party", PolicyDecisionOutcome.allow, "AllowFirstPartyAtomicNodes"),
        ("atomic", "external", PolicyDecisionOutcome.deny, None),
        ("composite", None, PolicyDecisionOutcome.allow, "AllowCompositeNodes"),
    ],
)
def test_first_party_atomic_only_policy(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    trust_tier: str | None,
    expected_outcome: PolicyDecisionOutcome,
    expected_sid: str | None,
) -> None:
    monkeypatch.delenv("JARVIS_POLICY_PROFILE", raising=False)
    monkeypatch.setenv("JARVIS_POLICY_PATH", _sample_policy_path())

    extensions: dict[str, Any] = {"jarvis.trust_tier": trust_tier} if trust_tier is not None else {}
    node_type = NodeType(
        node_type_id="jarvis.web.fetch" if kind == "atomic" else "jarvis.composite.planner.general",
        version="0.3.7",
        kind=NodeKind(kind),
        extensions=Extensions.model_validate(extensions) if extensions else None,
    )
    node_registry: Any = _DummyNodeRegistry(node_type)
    service = PdpService(node_registry=node_registry)

    request = _pdp_request_for_node(node_type_id=node_type.node_type_id)
    result = asyncio.run(service.decide_policy(request))

    assert result.decision == expected_outcome
    assert result.message == expected_sid
