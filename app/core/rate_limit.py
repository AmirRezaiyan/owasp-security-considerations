from hashlib import sha256

from fastapi import HTTPException, Request, status
from redis.exceptions import RedisError

RATE_LIMIT_SCRIPT = """
local current = redis.call("INCR", KEYS[1])

if current == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end

local ttl = redis.call("TTL", KEYS[1])

return {current, ttl}
"""


def enforce_rate_limit(
    request: Request,
    action: str,
    limit: int,
    window_seconds: int,
) -> None:
    redis_client = getattr(request.app.state, "redis", None)

    if redis_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service is unavailable.",
        )

    client_ip = request.client.host if request.client is not None else "unknown"

    # Avoid storing raw client IP addresses in Redis keys.
    ip_hash = sha256(client_ip.encode("utf-8")).hexdigest()

    redis_key = f"rate_limit:{action}:{ip_hash}"

    try:
        result = redis_client.eval(
            RATE_LIMIT_SCRIPT,
            1,
            redis_key,
            window_seconds,
        )

    except RedisError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service is unavailable.",
        ) from None

    request_count, ttl = result

    if int(request_count) > limit:
        retry_after = max(int(ttl), 1)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={
                "Retry-After": str(retry_after),
            },
        )
