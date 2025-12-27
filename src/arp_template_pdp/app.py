from __future__ import annotations

from .service import PdpService
from .utils import auth_settings_from_env_or_dev_insecure


def create_app():
    return PdpService().create_app(
        title="ARP Template PDP",
        auth_settings=auth_settings_from_env_or_dev_insecure(),
    )


app = create_app()

