from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis import Redis
from redis.exceptions import RedisError

from app.api.router import api_router
from app.config import settings
from app.core.exceptions import register_exception_handlers
from app.database import create_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis_client = Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )

    app.state.redis = redis_client

    try:
        try:
            redis_client.ping()
        except RedisError as exc:
            raise RuntimeError(
                "Redis is unavailable. The application cannot start "
                "without its rate limiting service."
            ) from exc

        create_tables()

        yield

    finally:
        redis_client.close()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=("A practical laboratory for learning and testing the OWASP API Security Top 10."),
    debug=settings.debug,
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


register_exception_handlers(app)

app.include_router(api_router)


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy"}


@app.get("/", tags=["Root"])
def root():
    response = {
        "message": "Welcome to OWASP API Security Lab.",
        "health": "/health",
    }
    if not settings.is_production:
        response["documentation"] = "/docs"
    return response
