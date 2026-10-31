"""API10: external API data must be constrained and validated before use.

Scenario: a partner response contains malformed values or unexpected fields.
Network fetching is handled separately by the allowlisted ExternalAPIClient.
Reference: https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/.
"""

from pydantic import BaseModel, ConfigDict, Field

from app.vulnerabilities import require_vulnerable_demos_enabled


class PartnerRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=80)
    score: int = Field(ge=0, le=100)


def vulnerable_trust_partner_response(payload: dict[str, object]) -> dict[str, object]:
    """Demonstrate passing a third-party object through without validation."""
    require_vulnerable_demos_enabled()
    return payload


def validate_partner_response(payload: object) -> PartnerRecord:
    """Validate shape, types, bounds, and unknown fields before use."""
    return PartnerRecord.model_validate(payload)
