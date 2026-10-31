"""API7: SSRF occurs when a server fetches destinations controlled by callers.

Scenario: a URL field accepts a loopback address and the server makes the request.
The vulnerable helper only classifies text and never performs a network request.
Reference: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/.
"""

from app.services.external_api import ExternalAPIClient, ExternalAPIError
from app.vulnerabilities import require_vulnerable_demos_enabled


def vulnerable_url_accepted(url: str) -> bool:
    """Demonstrate scheme-only validation without making a network request."""
    require_vulnerable_demos_enabled()
    return url.startswith(("http://", "https://"))


def secure_validate_url(url: str, allowed_hosts: set[str]) -> bool:
    """Apply the outbound client's HTTPS, host, port, and literal-IP checks."""
    try:
        ExternalAPIClient(allowed_hosts)._validate_url(url)
    except (ExternalAPIError, ValueError):
        return False
    return True
