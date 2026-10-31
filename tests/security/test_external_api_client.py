import asyncio
import gzip
import socket

import aiohttp
import pytest
from aiohttp.base_protocol import BaseProtocol
from aiohttp.http_parser import DeflateBuffer
from aiohttp.streams import StreamReader
from pydantic import BaseModel, model_validator

from app.services.external_api import (
    ExternalAPIClient,
    ExternalAPIError,
    PublicDNSResolver,
    _read_limited,
)


class PartnerPayload(BaseModel):
    name: str
    score: int


class FakeContent:
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def iter_chunked(self, chunk_size: int):
        for chunk in self.chunks:
            yield chunk


class FakeResponse:
    def __init__(self, body: bytes | list[bytes], headers=None, status=200):
        self.content = FakeContent(body if isinstance(body, list) else [body])
        self.headers = headers or {"Content-Type": "application/json"}
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None


class FakeSession:
    def __init__(self, response: FakeResponse | None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.request_options = None
        self.client_options = None
        self.request_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        if self.client_options is not None:
            await self.client_options["connector"].close()

    def get(self, url, **kwargs):
        self.request_count += 1
        self.request_options = kwargs
        if self.error is not None:
            raise self.error
        return self.response


class FakeResolver:
    def __init__(self, records=None):
        self.records = (
            records
            if records is not None
            else [
                {
                    "hostname": "partner.example",
                    "host": "10.0.0.5",
                    "port": 443,
                    "family": socket.AF_INET,
                    "proto": 0,
                    "flags": 0,
                }
            ]
        )

    async def resolve(self, host, port, family):
        return self.records

    async def close(self):
        return None


def install_fake_session(monkeypatch, response=None, error=None):
    session = FakeSession(response, error)

    def create_session(**options):
        session.client_options = options
        return session

    monkeypatch.setattr(aiohttp, "ClientSession", create_session)
    return session


def test_external_client_rejects_untrusted_url_before_network(monkeypatch):
    client = ExternalAPIClient({"partner.example"})
    called = False

    def unexpected_session(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("network session must not be opened")

    monkeypatch.setattr(aiohttp, "ClientSession", unexpected_session)

    with pytest.raises(ExternalAPIError, match="URL is not allowed"):
        asyncio.run(client.fetch_json("http://partner.example/data", PartnerPayload))

    assert not called


@pytest.mark.parametrize(
    ("timeout_seconds", "max_response_bytes"),
    [(0, 100), (61, 100), (float("inf"), 100), (float("nan"), 100), (5, True)],
)
def test_external_client_rejects_invalid_resource_limits(timeout_seconds, max_response_bytes):
    with pytest.raises(ValueError):
        ExternalAPIClient(
            {"partner.example"},
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )


@pytest.mark.parametrize(
    "address",
    [
        "10.20.30.40",
        "169.254.169.254",
        "192.168.1.10",
        "172.16.0.1",
        "fd00::1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::",
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ],
)
def test_external_client_rejects_non_public_literal_addresses(address):
    host = f"[{address}]" if ":" in address else address
    client = ExternalAPIClient({address})

    with pytest.raises(ExternalAPIError, match="URL is not allowed"):
        asyncio.run(client.fetch_json(f"https://{host}/", PartnerPayload))


def test_external_client_rejects_untrusted_metadata_hostname(monkeypatch):
    client = ExternalAPIClient({"partner.example"})
    monkeypatch.setattr(
        aiohttp,
        "ClientSession",
        lambda **kwargs: pytest.fail("untrusted metadata host must not open a session"),
    )

    with pytest.raises(ExternalAPIError, match="URL is not allowed"):
        asyncio.run(client.fetch_json("https://metadata.google.internal/", PartnerPayload))


@pytest.mark.parametrize(
    "records",
    [
        [{"host": "10.0.0.5"}],
        [
            {"host": "8.8.8.8", "proto": 0, "flags": 0},
            {"host": "10.0.0.5", "proto": 0, "flags": 0},
        ],
        [None],
        [{"host": None}],
        [{"host": "8.8.8.8", "proto": "invalid", "flags": 0}],
        [{"host": "8.8.8.8", "proto": 0, "flags": "invalid"}],
    ],
)
def test_public_resolver_rejects_private_mixed_and_malformed_records(records):
    async def resolve_records():
        resolver = PublicDNSResolver()
        resolver._resolver = FakeResolver(records=records)

        with pytest.raises(OSError, match="Host resolution failed"):
            await resolver.resolve("partner.example", 443, socket.AF_INET)

    asyncio.run(resolve_records())


@pytest.mark.parametrize("host", ["2130706433", "127.1", "0x7f000001"])
def test_public_resolver_rejects_alternative_private_ip_representations(host):
    async def resolve_alternative_ip():
        resolver = PublicDNSResolver()
        resolver._resolver = FakeResolver(records=[{"host": "127.0.0.1", "proto": 0, "flags": 0}])

        with pytest.raises(OSError, match="Host resolution failed"):
            await resolver.resolve(host, 443, socket.AF_INET)

    asyncio.run(resolve_alternative_ip())


def test_aiohttp_connection_handoff_uses_validated_ip_under_dns_rebinding(monkeypatch):
    public_answer = {
        "hostname": "partner.example",
        "host": "8.8.8.8",
        "port": 443,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": 0,
    }

    class RebindingResolver:
        def __init__(self):
            self.calls = 0

        async def resolve(self, host, port, family):
            self.calls += 1
            if self.calls == 1:
                return [public_answer]
            return [{**public_answer, "host": "127.0.0.1"}]

        async def close(self):
            return None

    connectors = []

    class CapturingConnector(aiohttp.TCPConnector):
        def __init__(self, *args, **kwargs):
            self.rebinding_resolver = RebindingResolver()
            self.public_resolver = kwargs["resolver"]
            self.public_resolver._resolver = self.rebinding_resolver
            self.dial_addresses = []
            connectors.append(self)
            super().__init__(*args, **kwargs)

        async def _wrap_create_connection(
            self,
            protocol_factory,
            *,
            timeout,
            addr_infos,
            req,
            client_error,
            **kwargs,
        ):
            self.dial_addresses.extend(address_info[4][0] for address_info in addr_infos)
            raise client_error(req.connection_key, OSError("test stops before socket creation"))

    monkeypatch.setattr(aiohttp, "TCPConnector", CapturingConnector)

    async def request_without_socket():
        client = ExternalAPIClient({"partner.example"})
        with pytest.raises(ExternalAPIError, match="request or response"):
            await client.fetch_json("https://partner.example/data", PartnerPayload)

        connector = connectors[0]
        assert connector.dial_addresses == ["8.8.8.8"]
        assert connector.rebinding_resolver.calls == 1
        with pytest.raises(OSError, match="Host resolution failed"):
            await connector.public_resolver.resolve("partner.example", 443, socket.AF_INET)
        assert connector.rebinding_resolver.calls == 2

    asyncio.run(request_without_socket())


def test_dns_resolution_failure_is_sanitized_without_dialing(monkeypatch):
    class FailingResolver:
        async def resolve(self, host, port, family):
            raise OSError("private resolver detail")

        async def close(self):
            return None

    class ResolverFailureConnector(aiohttp.TCPConnector):
        def __init__(self, *args, **kwargs):
            kwargs["resolver"]._resolver = FailingResolver()
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(aiohttp, "TCPConnector", ResolverFailureConnector)

    async def fetch():
        client = ExternalAPIClient({"partner.example"})
        with pytest.raises(ExternalAPIError) as error:
            await client.fetch_json("https://partner.example/data", PartnerPayload)
        assert "private resolver detail" not in str(error.value)

    asyncio.run(fetch())


def test_external_client_normalizes_idna_and_rejects_unsafe_url_forms():
    client = ExternalAPIClient({"BÜCHER.EXAMPLE."})

    assert client._validate_url("HTTPS://bücher.example:443") == (
        "https://xn--bcher-kva.example:443/"
    )
    for url in (
        "https://user:pass@xn--bcher-kva.example/",
        "https://xn--bcher-kva.example:8443/",
        "https://xn--bcher-kva.example/#fragment",
        "https://%78n--bcher-kva.example/",
        "https://[2001:4860:4860::8888%25eth0]/",
        "https://xn--bcher-kva.example:invalid/",
        "https://[invalid]/",
        "https://xn--bcher-kva.example\n@attacker.example/",
    ):
        with pytest.raises(ExternalAPIError, match="URL is not allowed"):
            client._validate_url(url)


def test_external_client_preserves_query_and_adds_empty_path():
    client = ExternalAPIClient({"partner.example"})

    assert client._validate_url("https://partner.example?mode=compact") == (
        "https://partner.example/?mode=compact"
    )


@pytest.mark.parametrize(
    "location",
    ["http://127.0.0.1/admin", "https://unauthorized.example/"],
)
def test_redirect_response_is_rejected_without_following_it(monkeypatch, location):
    response = FakeResponse(b"", headers={"Location": location}, status=302)
    session = install_fake_session(monkeypatch, response)
    client = ExternalAPIClient({"partner.example"})

    with pytest.raises(ExternalAPIError, match="unsuccessful response"):
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert session.request_count == 1
    assert session.request_options["allow_redirects"] is False


def test_external_client_validates_response_and_sets_safe_session_options(monkeypatch):
    response = FakeResponse(
        b'{"name":"partner","score":7}',
        headers={"Content-Type": "Application/JSON; charset=utf-8"},
    )
    session = install_fake_session(monkeypatch, response)
    client = ExternalAPIClient({"partner.example"})

    result = asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert result == PartnerPayload(name="partner", score=7)
    assert session.request_options["allow_redirects"] is False
    assert session.client_options["trust_env"] is False
    assert session.client_options["auto_decompress"] is True
    assert session.client_options["timeout"].total == 5.0
    assert session.client_options["timeout"].connect == 5.0
    assert session.client_options["timeout"].sock_read == 5.0


def test_external_client_rejects_unexpected_content_type(monkeypatch):
    session = install_fake_session(
        monkeypatch,
        FakeResponse(b"not json", headers={"Content-Type": "text/html"}),
    )
    client = ExternalAPIClient({"partner.example"})

    with pytest.raises(ExternalAPIError, match="unsupported content type"):
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert session.request_count == 1


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        ([b"1234", b"5678", b"9"], {"Content-Type": "application/json"}),
        ([b"1234", b"56789"], {"Content-Type": "application/json", "Content-Length": "1"}),
    ],
)
def test_external_client_caps_chunked_response_stream(monkeypatch, body, headers):
    session = install_fake_session(monkeypatch, FakeResponse(body, headers=headers))
    client = ExternalAPIClient({"partner.example"}, max_response_bytes=8)

    with pytest.raises(ExternalAPIError, match="size limit"):
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert session.client_options["auto_decompress"] is True


def test_stream_limit_applies_to_aiohttp_decompressed_bytes():
    async def enforce_decompressed_limit():
        loop = asyncio.get_running_loop()
        response_stream = StreamReader(BaseProtocol(loop), limit=1024, loop=loop)
        decompressor = DeflateBuffer(response_stream, "gzip")
        compressed_body = gzip.compress(b"123456789")
        decompressor.feed_data(compressed_body, len(compressed_body))
        decompressor.feed_eof()

        with pytest.raises(ExternalAPIError, match="size limit"):
            await _read_limited(response_stream, max_bytes=8)

    asyncio.run(enforce_decompressed_limit())


@pytest.mark.parametrize("content_length", ["-1", "not-a-number"])
def test_external_client_rejects_invalid_content_length(monkeypatch, content_length):
    session = install_fake_session(
        monkeypatch,
        FakeResponse(
            b"{}",
            headers={"Content-Type": "application/json", "Content-Length": content_length},
        ),
    )
    client = ExternalAPIClient({"partner.example"})

    with pytest.raises(ExternalAPIError, match="size is invalid"):
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert session.request_count == 1


def test_external_client_rejects_declared_oversized_content(monkeypatch):
    session = install_fake_session(
        monkeypatch,
        FakeResponse(
            b"{}",
            headers={"Content-Type": "application/json", "Content-Length": "9"},
        ),
    )
    client = ExternalAPIClient({"partner.example"}, max_response_bytes=8)

    with pytest.raises(ExternalAPIError, match="size limit"):
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert session.response.content.chunks == [b"{}"]


def test_external_client_sanitizes_schema_errors(monkeypatch):
    install_fake_session(monkeypatch, FakeResponse(b'{"name":"partner","score":"bad"}'))
    client = ExternalAPIClient({"partner.example"})

    with pytest.raises(ExternalAPIError) as error:
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert "score" not in str(error.value)
    assert "bad" not in str(error.value)


@pytest.mark.parametrize("body", [b"\xff", b"[" * 2000 + b"]" * 2000])
def test_external_client_sanitizes_invalid_utf8_and_deep_json(monkeypatch, body):
    install_fake_session(monkeypatch, FakeResponse(body))
    client = ExternalAPIClient({"partner.example"})

    with pytest.raises(ExternalAPIError, match="request or response") as error:
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert "\xff" not in str(error.value)


def test_external_client_sanitizes_unexpected_response_model_exception(monkeypatch):
    class ExplodingPayload(BaseModel):
        @model_validator(mode="before")
        @classmethod
        def fail_validation(cls, value):
            raise RuntimeError("sensitive validator detail")

    install_fake_session(monkeypatch, FakeResponse(b"{}"))
    client = ExternalAPIClient({"partner.example"})

    with pytest.raises(ExternalAPIError) as error:
        asyncio.run(client.fetch_json("https://partner.example/data", ExplodingPayload))

    assert "sensitive validator detail" not in str(error.value)


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("secret timeout detail"), aiohttp.ClientConnectionError("private host detail")],
)
def test_external_client_sanitizes_timeout_and_connection_failures(monkeypatch, failure):
    install_fake_session(monkeypatch, error=failure)
    client = ExternalAPIClient({"partner.example"})

    with pytest.raises(ExternalAPIError, match="request or response") as error:
        asyncio.run(client.fetch_json("https://partner.example/data", PartnerPayload))

    assert "secret timeout detail" not in str(error.value)
    assert "private host detail" not in str(error.value)
