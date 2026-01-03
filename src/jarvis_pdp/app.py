from __future__ import annotations

import logging
import os

from .auth import auth_client_from_env_optional
from .clients import NodeRegistryGatewayClient
from .service import PdpService
from .utils import auth_settings_from_env_or_dev_insecure

logger = logging.getLogger(__name__)


def create_app():
    node_registry_url = (os.environ.get("JARVIS_NODE_REGISTRY_URL") or "").strip()
    logger.info("PDP config (node_registry=%s)", bool(node_registry_url))
    node_registry = None
    if node_registry_url:
        if (auth_client := auth_client_from_env_optional()) is None:
            raise RuntimeError("ARP_AUTH_CLIENT_ID and ARP_AUTH_CLIENT_SECRET are required for outbound auth.")
        node_registry = NodeRegistryGatewayClient(
            base_url=node_registry_url,
            auth_client=auth_client,
            audience=(os.environ.get("JARVIS_NODE_REGISTRY_AUDIENCE") or "arp-jarvis-noderegistry").strip() or None,
        )
    auth_settings = auth_settings_from_env_or_dev_insecure()
    logger.info(
        "PDP auth settings (mode=%s, issuer=%s)",
        auth_settings.mode,
        auth_settings.issuer,
    )
    return PdpService(node_registry=node_registry).create_app(
        title="JARVIS PDP",
        auth_settings=auth_settings,
    )


app = create_app()
