import pytest
from pydantic import ValidationError

from app.vulnerabilities.api10_unsafe_consumption import (
    validate_partner_response,
    vulnerable_trust_partner_response,
)


def test_unsafe_consumption_demo_validates_partner_data(enable_vulnerable_demos):
    payload = {"name": "partner", "score": 80}
    assert vulnerable_trust_partner_response(payload) is payload
    assert validate_partner_response(payload).model_dump() == {
        "name": "partner",
        "score": 80,
    }


def test_partner_response_accepts_boundary_values():
    minimum = validate_partner_response({"name": "x", "score": 0})
    maximum = validate_partner_response({"name": "x" * 80, "score": 100})

    assert minimum.score == 0
    assert len(maximum.name) == 80
    assert maximum.score == 100


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "partner", "score": 101},
        {"name": "partner", "score": 80, "admin": True},
        {"name": "", "score": 80},
        {},
        {"name": "partner"},
        {"name": 12, "score": 10},
        {"name": "partner", "score": True},
        {"name": "partner", "score": 10.5},
        {"name": "x" * 81, "score": 10},
        {"name": "partner", "score": -1},
        {"name": "partner", "score": 10, "unexpected": "value"},
        None,
        ["partner", 10],
    ],
)
def test_partner_response_rejects_missing_unknown_and_malformed_payloads(payload):
    with pytest.raises(ValidationError):
        validate_partner_response(payload)
