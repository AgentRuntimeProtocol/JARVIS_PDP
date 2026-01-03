from __future__ import annotations

import logging
import os
from typing import Any

from arp_policy import Enforcer, Policy, PolicyError

from arp_standard_model import (
    Health,
    Extensions,
    NodeType,
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
from arp_standard_server import ArpServerError

from . import __version__
from .clients import NodeRegistryGatewayClient
from .utils import now

logger = logging.getLogger(__name__)


class PdpService(BasePdpServer):
    """Policy decision surface; plug your governance logic here."""

    # Core method - API surface and main extension points
    def __init__(
        self,
        *,
        service_name: str = "arp-jarvis-pdp",
        service_version: str = __version__,
        node_registry: NodeRegistryGatewayClient | None = None,
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
        self._node_registry = node_registry

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
        return await self._decide(request.body)

    def _build_context(self, request: PolicyDecisionRequest) -> dict[str, Any]:
        context: dict[str, Any] = dict(request.context or {})
        if request.run_id:
            context["run_id"] = request.run_id
        if request.node_run_id:
            context["node_run_id"] = request.node_run_id
        if request.node_type_ref:
            context["node_type_id"] = request.node_type_ref.node_type_id
            context["node_type_version"] = request.node_type_ref.version
        if request.run_context:
            context["run_context"] = request.run_context.model_dump(exclude_none=True)
        return context

    def _resolve_resource(self, request: PolicyDecisionRequest, context: dict[str, Any]) -> str:
        resource = context.get("resource")
        if isinstance(resource, str) and resource:
            return resource
        if request.node_type_ref:
            return f"node_type:{request.node_type_ref.node_type_id}"
        if request.run_id:
            return f"run:{request.run_id}"
        return "run:*"

    def _load_policy(self, path: str) -> Policy:
        return Policy.load(path)

    async def _decide(self, request: PolicyDecisionRequest) -> PolicyDecision:
        logger.info(
            "Policy decision requested (action=%s, run_id=%s, node_run_id=%s, node_type_id=%s)",
            request.action,
            request.run_id,
            request.node_run_id,
            request.node_type_ref.node_type_id if request.node_type_ref else None,
        )
        profile = (os.environ.get("JARVIS_POLICY_PROFILE") or "").strip().lower()
        if profile == "dev-allow":
            logger.info("Policy decision dev-allow (action=%s)", request.action)
            return PolicyDecision(decision=PolicyDecisionOutcome.allow, reason_code="dev_allow")
        if profile and profile not in {"dev-allow"}:
            logger.warning("Policy profile unsupported (profile=%s)", profile)
            return PolicyDecision(
                decision=PolicyDecisionOutcome.deny,
                reason_code="invalid_policy_profile",
                message=f"Unsupported JARVIS_POLICY_PROFILE: {profile}",
            )

        policy_path = (os.environ.get("JARVIS_POLICY_PATH") or "").strip()
        if not policy_path:
            policy_path = (os.environ.get("ARP_POLICY_PATH") or "").strip()

        if policy_path:
            try:
                policy = self._load_policy(policy_path)
            except PolicyError as exc:
                logger.warning("Policy load failed (path=%s, error=%s)", policy_path, exc)
                return PolicyDecision(
                    decision=PolicyDecisionOutcome.deny,
                    reason_code="invalid_policy",
                    message=str(exc),
                )
            logger.info(
                "Policy loaded (path=%s, hash=%s, version=%s)",
                policy_path,
                policy.policy_hash,
                policy.version,
            )
            enforcer = Enforcer(policy)
            context = self._build_context(request)
            if request.node_type_ref:
                if self._node_registry is None:
                    logger.warning("Policy requires Node Registry but it is not configured")
                    return PolicyDecision(
                        decision=PolicyDecisionOutcome.deny,
                        reason_code="node_registry_unconfigured",
                        message="Node Registry is required to evaluate node_type policy requests",
                    )
                try:
                    node_type = await self._node_registry.get_node_type(
                        request.node_type_ref.node_type_id,
                        request.node_type_ref.version,
                    )
                except ArpServerError as exc:
                    logger.warning(
                        "NodeType metadata lookup failed (code=%s, node_type_id=%s)",
                        exc.code,
                        request.node_type_ref.node_type_id,
                    )
                    return PolicyDecision(
                        decision=PolicyDecisionOutcome.deny,
                        reason_code=exc.code,
                        message="NodeType metadata lookup failed",
                    )
                except Exception:
                    logger.exception("NodeType metadata lookup failed")
                    return PolicyDecision(
                        decision=PolicyDecisionOutcome.deny,
                        reason_code="node_type_metadata_unavailable",
                        message="NodeType metadata lookup failed",
                    )
                self._enrich_node_type_context(context, node_type)
            resource = self._resolve_resource(request, context)
            decision = enforcer.authorize(request.action, resource, context)
            outcome = PolicyDecisionOutcome.allow if decision.allowed else PolicyDecisionOutcome.deny
            logger.info(
                "Policy decision computed (action=%s, resource=%s, decision=%s, reason=%s)",
                request.action,
                resource,
                outcome.value if hasattr(outcome, "value") else outcome,
                decision.reason,
            )
            return PolicyDecision(
                decision=outcome,
                reason_code=decision.reason,
                message=decision.matched_statement_id,
                extensions=Extensions.model_validate(
                    {"policy_hash": policy.policy_hash, "policy_version": policy.version}
                ),
            )

        legacy_mode = (os.environ.get("ARP_POLICY_MODE") or "").strip().lower()
        if legacy_mode == "allow_all":
            logger.info("Policy legacy allow_all in effect")
            return PolicyDecision(decision=PolicyDecisionOutcome.allow, reason_code="allow_all")
        if legacy_mode == "file":
            logger.warning("Policy legacy file mode missing policy path")
            return PolicyDecision(
                decision=PolicyDecisionOutcome.deny,
                reason_code="missing_policy_path",
                message="ARP_POLICY_PATH or JARVIS_POLICY_PATH is required when ARP_POLICY_MODE=file",
            )

        logger.warning("Policy unconfigured; denying by default")
        return PolicyDecision(
            decision=PolicyDecisionOutcome.deny,
            reason_code="policy_unconfigured",
            message="No policy profile or policy file configured",
        )

    def _enrich_node_type_context(self, context: dict[str, Any], node_type: NodeType) -> None:
        """
        Enrich the policy context with NodeType metadata fetched from Node Registry.

        Callers should pass only `node_type_ref` and avoid duplicating NodeType metadata in the request.
        PDP treats Node Registry as the source-of-truth and overwrites any colliding keys.
        """
        kind = node_type.kind.value if hasattr(node_type.kind, "value") else str(node_type.kind)
        jarvis: dict[str, Any] = {}
        raw_extensions = node_type.extensions.model_dump(exclude_none=True) if node_type.extensions else {}
        for key, value in raw_extensions.items():
            if not isinstance(key, str):
                continue
            if key.startswith("jarvis."):
                jarvis[key.removeprefix("jarvis.")] = value

        node_type_payload: dict[str, Any] = {
            "id": node_type.node_type_id,
            "version": node_type.version,
            "kind": kind,
        }
        if node_type.description:
            node_type_payload["description"] = node_type.description
        if jarvis:
            node_type_payload["jarvis"] = jarvis

        context["node_type"] = node_type_payload
        context["node_type_id"] = node_type.node_type_id
        context["node_type_version"] = node_type.version
