"""Isolated, opt-in simulations for the OWASP API Security Top 10 (2023)."""

from app.config import settings

OWASP_API_TOP_10 = {
    "API1": "Broken Object Level Authorization (BOLA)",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery (SSRF)",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}


def require_vulnerable_demos_enabled() -> None:
    if not settings.enable_vulnerable_demos or settings.is_production:
        raise RuntimeError(
            "Vulnerable demonstrations are disabled. Enable them only in an isolated lab."
        )


__all__ = ["OWASP_API_TOP_10", "require_vulnerable_demos_enabled"]
