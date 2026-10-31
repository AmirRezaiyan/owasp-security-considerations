import pytest
from fastapi.routing import iter_route_contexts

from app.api.router import api_router
from app.config import settings
from app.vulnerabilities.api1_bola import vulnerable_read_object
from app.vulnerabilities.api2_authentication import vulnerable_token_claims
from app.vulnerabilities.api3_property_authorization import vulnerable_update_profile
from app.vulnerabilities.api4_resource_consumption import vulnerable_page
from app.vulnerabilities.api5_function_authorization import vulnerable_admin_action
from app.vulnerabilities.api6_sensitive_flows import vulnerable_can_purchase
from app.vulnerabilities.api7_ssrf import vulnerable_url_accepted
from app.vulnerabilities.api8_misconfiguration import vulnerable_error_response
from app.vulnerabilities.api9_inventory import vulnerable_route_inventory
from app.vulnerabilities.api10_unsafe_consumption import vulnerable_trust_partner_response

VULNERABLE_DEMOS = [
    pytest.param(vulnerable_read_object, ({}, 1), id="api1"),
    pytest.param(vulnerable_token_claims, ("learner",), id="api2"),
    pytest.param(vulnerable_update_profile, ({}, {"is_admin": True}), id="api3"),
    pytest.param(vulnerable_page, ([],), id="api4"),
    pytest.param(vulnerable_admin_action, (), id="api5"),
    pytest.param(vulnerable_can_purchase, (), id="api6"),
    pytest.param(vulnerable_url_accepted, ("http://127.0.0.1/",), id="api7"),
    pytest.param(vulnerable_error_response, (RuntimeError("internal detail"),), id="api8"),
    pytest.param(vulnerable_route_inventory, ([],), id="api9"),
    pytest.param(vulnerable_trust_partner_response, ({"untrusted": True},), id="api10"),
]


@pytest.mark.parametrize(("demo", "args"), VULNERABLE_DEMOS)
def test_vulnerable_demo_functions_require_explicit_enablement(monkeypatch, demo, args):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "enable_vulnerable_demos", False)

    with pytest.raises(RuntimeError, match="disabled"):
        demo(*args)


@pytest.mark.parametrize(("demo", "args"), VULNERABLE_DEMOS)
def test_vulnerable_demo_functions_remain_disabled_in_production(
    monkeypatch,
    demo,
    args,
):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "enable_vulnerable_demos", True)

    with pytest.raises(RuntimeError, match="disabled"):
        demo(*args)


@pytest.mark.parametrize("environment", ["production", " Production ", "PRODUCTION", "prod"])
def test_production_mode_normalization_cannot_bypass_demo_guard(monkeypatch, environment):
    monkeypatch.setattr(settings, "environment", environment)
    monkeypatch.setattr(settings, "enable_vulnerable_demos", True)

    with pytest.raises(RuntimeError, match="disabled"):
        vulnerable_token_claims("learner")


def test_vulnerable_demo_functions_are_not_mounted_as_http_routes():
    route_contexts = list(iter_route_contexts(api_router.routes))

    assert route_contexts, "Expected API routes to be registered."

    endpoints = [context.endpoint for context in route_contexts]

    assert all(endpoint is not None for endpoint in endpoints)

    assert all(not endpoint.__module__.startswith("app.vulnerabilities") for endpoint in endpoints)
