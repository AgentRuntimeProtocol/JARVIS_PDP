from __future__ import annotations

import json
import os
from pathlib import Path

from arp_standard_model import (
    Health,
    PdpDecidePolicyRequest,
    PdpHealthRequest,
    PdpVersionRequest,
    PolicyDecision,
    PolicyDecisionOutcome,
    PolicyDecisionRequest,
    Status,
    VersionInfo,
)
from arp_standard_server.pdp import BasePdpServer

from . import __version__
from .utils import now


class PdpService(BasePdpServer):
    """Policy decision surface; plug your governance logic here."""

    # Core method - API surface and main extension points
    def __init__(
        self,
        *,
        service_name: str = "arp-template-pdp",
        service_version: str = __version__,
    ) -> None:
        """
        Not part of ARP spec; required to construct the PDP.

        Args:
          - service_name: Name exposed by /v1/version.
          - service_version: Version exposed by /v1/version.

        Potential modifications:
          - Inject a policy client (OPA, internal policy service).
          - Cache policies or load them from a database.
        """
        self._service_name = service_name
        self._service_version = service_version

    # Core methods - PDP API implementations
    async def health(self, request: PdpHealthRequest) -> Health:
        """
        Mandatory: Required by the ARP PDP API.

        Args:
          - request: PdpHealthRequest (unused).
        """
        _ = request
        return Health(status=Status.ok, time=now())

    async def version(self, request: PdpVersionRequest) -> VersionInfo:
        """
        Mandatory: Required by the ARP PDP API.

        Args:
          - request: PdpVersionRequest (unused).
        """
        _ = request
        return VersionInfo(
            service_name=self._service_name,
            service_version=self._service_version,
            supported_api_versions=["v1"],
        )

    async def decide_policy(self, request: PdpDecidePolicyRequest) -> PolicyDecision:
        """
        Mandatory: Required by the ARP PDP API.

        Args:
          - request: PdpDecidePolicyRequest with action + context.

        Potential modifications:
          - Query your custom policy engine (OPA, ABAC/RBAC, approvals).
          - Apply environment-specific enforcement rules.
        """
        return self._decide(request.body)

    # Helpers (internal): implementation detail for the template.
    def _load_policy_file(self, path: Path) -> dict:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Policy file must be a JSON object.")
        return payload

    def _decide(self, request: PolicyDecisionRequest) -> PolicyDecision:
        mode = (os.environ.get("ARP_POLICY_MODE") or "allow_all").strip().lower()
        if mode == "allow_all":
            return PolicyDecision(decision=PolicyDecisionOutcome.allow, reason_code="allow_all")

        if mode == "file":
            raw_path = (os.environ.get("ARP_POLICY_PATH") or "").strip()
            if not raw_path:
                return PolicyDecision(
                    decision=PolicyDecisionOutcome.deny,
                    reason_code="missing_policy_path",
                    message="ARP_POLICY_PATH is required when ARP_POLICY_MODE=file",
                )
            policy = self._load_policy_file(Path(raw_path))
            deny = set(policy.get("deny_actions") or [])
            require = set(policy.get("require_approval_actions") or [])
            action = request.action
            if action in deny:
                return PolicyDecision(decision=PolicyDecisionOutcome.deny, reason_code="deny_action", message=action)
            if action in require:
                return PolicyDecision(
                    decision=PolicyDecisionOutcome.require_approval,
                    reason_code="require_approval_action",
                    message=action,
                )
            return PolicyDecision(decision=PolicyDecisionOutcome.allow, reason_code="allow_default")

        return PolicyDecision(
            decision=PolicyDecisionOutcome.deny,
            reason_code="invalid_policy_mode",
            message=f"Unsupported ARP_POLICY_MODE: {mode}",
        )
