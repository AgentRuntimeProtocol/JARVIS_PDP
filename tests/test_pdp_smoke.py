import asyncio

from arp_standard_model import PdpDecidePolicyRequest, PolicyDecisionOutcome, PolicyDecisionRequest
from arp_template_pdp.service import PdpService


def test_allow_all_default() -> None:
    service = PdpService()
    request = PdpDecidePolicyRequest(body=PolicyDecisionRequest(action="run.start"))

    result = asyncio.run(service.decide_policy(request))

    assert result.decision == PolicyDecisionOutcome.allow
