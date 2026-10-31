from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEVELOPMENT_SECRET_KEY = "development-only-change-this-secret-before-deployment"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "OWASP API Security Lab"
    app_version: str = "1.0.0"

    debug: bool = False
    environment: Literal["development", "test", "production"] = "development"
    enable_vulnerable_demos: bool = False

    database_url: str = "sqlite:///./owasp_lab.db"

    secret_key: str = Field(
        default=DEVELOPMENT_SECRET_KEY,
        min_length=32,
    )

    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = Field(default=30, gt=0)

    redis_url: str = "redis://localhost:6379/0"

    login_rate_limit: int = Field(default=5, gt=0)
    login_rate_limit_window_seconds: int = Field(default=60, gt=0)

    register_rate_limit: int = Field(default=5, gt=0)
    register_rate_limit_window_seconds: int = Field(default=3600, gt=0)

    cors_origins: str = "http://localhost:3000,http://localhost:5173"

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("ENVIRONMENT must be development, test, or production.")

        normalized = value.strip().casefold()

        if normalized == "prod":
            normalized = "production"

        if normalized not in {"development", "test", "production"}:
            raise ValueError("ENVIRONMENT must be development, test, or production.")

        return normalized

    @property
    def normalized_environment(self) -> str:
        if not isinstance(self.environment, str):
            return ""

        normalized = self.environment.strip().casefold()

        if normalized == "prod":
            return "production"

        return normalized

    @property
    def is_production(self) -> bool:
        # Fail closed if the runtime environment is invalid or unexpected.
        return self.normalized_environment not in {"development", "test"}

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @model_validator(mode="after")
    def validate_production_settings(self):
        if self.is_production:
            if self.enable_vulnerable_demos:
                raise ValueError("Vulnerable demonstrations must be disabled in production.")

            is_uniform_placeholder = self.secret_key == self.secret_key[0] * len(self.secret_key)

            if (
                self.secret_key.startswith("development-only-")
                or len(self.secret_key) < 64
                or is_uniform_placeholder
            ):
                raise ValueError(
                    "Production requires a non-default SECRET_KEY of at least 64 characters."
                )

            if self.debug:
                raise ValueError("DEBUG must be disabled in production.")

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
