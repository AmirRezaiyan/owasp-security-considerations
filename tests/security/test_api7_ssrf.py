from app.vulnerabilities.api7_ssrf import secure_validate_url, vulnerable_url_accepted


def test_ssrf_demo_never_fetches_and_secure_validation_blocks_local_destinations(
    enable_vulnerable_demos,
):
    local_url = "http://127.0.0.1/admin"

    assert vulnerable_url_accepted(local_url)
    assert not secure_validate_url(local_url, {"127.0.0.1"})
    assert secure_validate_url("https://partner.example/v1", {"partner.example"})
    assert not secure_validate_url("https://other.example/", {"partner.example"})
