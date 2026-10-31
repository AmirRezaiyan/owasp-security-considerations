import ipaddress
import json
import math
import socket
from typing import TypeVar
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver
from pydantic import BaseModel

ResponseModel = TypeVar("ResponseModel", bound=BaseModel)


def _is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped_address = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    classified_address = mapped_address or address
    return (
        classified_address.is_global
        and not classified_address.is_private
        and not classified_address.is_loopback
        and not classified_address.is_link_local
        and not classified_address.is_multicast
        and not classified_address.is_reserved
        and not classified_address.is_unspecified
        and getattr(address, "scope_id", None) is None
    )


class ExternalAPIError(Exception):
    """A sanitized error returned for rejected or invalid external responses."""


class PublicDNSResolver(AbstractResolver):
    """Resolve hostnames only when every result is a globally routable address."""

    def __init__(self) -> None:
        self._resolver = DefaultResolver()

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: int = socket.AF_INET,
    ) -> list[dict[str, object]]:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            records = await self._resolver.resolve(host, port, family)
            if not records:
                raise OSError("Host resolution failed") from None

            validated_records = []
            for record in records:
                try:
                    record_host = record.get("host")
                    protocol = record.get("proto", 0)
                    flags = record.get("flags", 0)
                    if (
                        not isinstance(record_host, str)
                        or type(protocol) is not int
                        or type(flags) is not int
                    ):
                        raise ValueError
                    resolved_address = ipaddress.ip_address(record_host)
                except (AttributeError, TypeError, ValueError):
                    raise OSError("Host resolution failed") from None
                if not _is_public_address(resolved_address):
                    raise OSError("Host resolution failed") from None
                validated_records.append(
                    {
                        "hostname": host,
                        "host": str(resolved_address),
                        "port": port,
                        "family": socket.AF_INET
                        if resolved_address.version == 4
                        else socket.AF_INET6,
                        "proto": protocol,
                        "flags": flags,
                    }
                )
            return validated_records

        if not _is_public_address(address):
            raise OSError("Host resolution failed") from None

        return [
            {
                "hostname": host,
                "host": str(address),
                "port": port,
                "family": socket.AF_INET if address.version == 4 else socket.AF_INET6,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        await self._resolver.close()


async def _read_limited(content: aiohttp.StreamReader, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0

    async for chunk in content.iter_chunked(64 * 1024):
        size += len(chunk)
        if size > max_bytes:
            raise ExternalAPIError("External response exceeded the size limit.")
        chunks.append(chunk)

    return b"".join(chunks)


class ExternalAPIClient:
    """Fetch and validate JSON from explicitly configured public HTTPS hosts."""

    def __init__(
        self,
        allowed_hosts: set[str],
        *,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        if not allowed_hosts:
            raise ValueError("At least one external API host must be allowed.")
        if (
            type(timeout_seconds) not in (int, float)
            or timeout_seconds <= 0
            or timeout_seconds > 60
            or (isinstance(timeout_seconds, float) and not math.isfinite(timeout_seconds))
            or type(max_response_bytes) is not int
            or max_response_bytes <= 0
        ):
            raise ValueError("Timeout and response-size limits are outside the allowed range.")

        self.allowed_hosts = frozenset(self._normalize_host(host) for host in allowed_hosts)
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    @staticmethod
    def _normalize_host(host: str) -> str:
        normalized = host.rstrip(".").lower()
        try:
            return normalized.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("Invalid configured external API host.") from None

    def _validate_url(self, url: str) -> str:
        if (
            not isinstance(url, str)
            or not url
            or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url)
        ):
            raise ExternalAPIError("External API URL is not allowed.")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            raise ExternalAPIError("External API URL is not allowed.") from None

        if (
            parsed.scheme.lower() != "https"
            or host is None
            or parsed.username is not None
            or parsed.password is not None
            or "#" in url
            or port not in (None, 443)
        ):
            raise ExternalAPIError("External API URL is not allowed.")

        try:
            normalized_host = self._normalize_host(host)
        except ValueError:
            raise ExternalAPIError("External API URL is not allowed.") from None
        if normalized_host not in self.allowed_hosts:
            raise ExternalAPIError("External API URL is not allowed.")

        try:
            address = ipaddress.ip_address(normalized_host)
        except ValueError:
            pass
        else:
            if not _is_public_address(address):
                raise ExternalAPIError("External API URL is not allowed.")

        formatted_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        netloc = f"{formatted_host}:443" if port == 443 else formatted_host
        return urlunsplit(("https", netloc, parsed.path or "/", parsed.query, ""))

    async def fetch_json(
        self,
        url: str,
        response_model: type[ResponseModel],
    ) -> ResponseModel:
        validated_url = self._validate_url(url)
        resolver = PublicDNSResolver()
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            use_dns_cache=False,
            limit=10,
        )
        timeout = aiohttp.ClientTimeout(
            total=self.timeout_seconds,
            connect=self.timeout_seconds,
            sock_read=self.timeout_seconds,
        )

        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                trust_env=False,
                auto_decompress=True,
            ) as session:
                async with session.get(
                    validated_url,
                    allow_redirects=False,
                    headers={"Accept": "application/json"},
                ) as response:
                    if not 200 <= response.status < 300:
                        raise ExternalAPIError("External API returned an unsuccessful response.")

                    content_type = (
                        response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                    )
                    if not (content_type == "application/json" or content_type.endswith("+json")):
                        raise ExternalAPIError("External API returned an unsupported content type.")

                    content_length = response.headers.get("Content-Length")
                    if content_length is not None:
                        try:
                            declared_size = int(content_length)
                            if declared_size < 0:
                                raise ExternalAPIError("External response size is invalid.")
                            if declared_size > self.max_response_bytes:
                                raise ExternalAPIError("External response exceeded the size limit.")
                        except ValueError:
                            raise ExternalAPIError("External response size is invalid.") from None

                    response_body = await _read_limited(
                        response.content,
                        self.max_response_bytes,
                    )
                    payload = json.loads(response_body)
                    return response_model.model_validate(payload)

        except ExternalAPIError:
            raise
        except Exception:
            raise ExternalAPIError("External API request or response validation failed.") from None
