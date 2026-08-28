"""Application configuration.

Every secret is a ``SecretStr`` so it cannot be printed by accident. The settings
object refuses to load when any secret still holds a ``.env.example`` placeholder and
the environment is not ``test`` — this is what makes ``make bootstrap`` mandatory
rather than optional (decision F-1 / ADR-011).
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL

PLACEHOLDER_MARKER = "REPLACE_ME"
"""Any secret containing this substring is treated as unset."""


class Environment(StrEnum):
    development = "development"
    test = "test"
    production = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- application
    env: Environment = Environment.development
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    app_name: str = "aegisnet"

    # ---- api
    api_host: str = "0.0.0.0"  # noqa: S104 - bound inside the container only; published on 127.0.0.1
    api_port: int = 8000
    api_cors_origins: str = "http://127.0.0.1:3000"
    secret_key: SecretStr = SecretStr(f"__{PLACEHOLDER_MARKER}__")

    # ---- postgres
    postgres_host: str = "db"
    postgres_port: int = 5432
    postgres_db: str = "aegisnet"
    postgres_app_user: str = "aegisnet_app"
    postgres_app_password: SecretStr = SecretStr(f"__{PLACEHOLDER_MARKER}__")
    postgres_migrator_user: str = "aegisnet_migrator"
    postgres_migrator_password: SecretStr = SecretStr(f"__{PLACEHOLDER_MARKER}__")

    # ---- redis
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_password: SecretStr = SecretStr(f"__{PLACEHOLDER_MARKER}__")

    # ---- operational limits used by the health probes
    probe_timeout_seconds: Annotated[float, Field(gt=0, le=30)] = 3.0

    @field_validator("api_cors_origins")
    @classmethod
    def _strip_origins(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def _reject_placeholders(self) -> Settings:
        """Refuse to run with template secrets outside the test environment."""
        if self.env is Environment.test:
            return self
        offenders = [
            name
            for name, value in (
                ("SECRET_KEY", self.secret_key),
                ("POSTGRES_APP_PASSWORD", self.postgres_app_password),
                ("POSTGRES_MIGRATOR_PASSWORD", self.postgres_migrator_password),
                ("REDIS_PASSWORD", self.redis_password),
            )
            if PLACEHOLDER_MARKER in value.get_secret_value()
        ]
        if offenders:
            raise ValueError(
                "refusing to start with placeholder secrets: "
                + ", ".join(sorted(offenders))
                + " — run `make bootstrap` to generate a local .env"
            )
        return self

    @model_validator(mode="after")
    def _debug_forbidden_in_production(self) -> Settings:
        if self.env is Environment.production and self.debug:
            raise ValueError("DEBUG must be false when ENV=production")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cors_origin_list(self) -> list[str]:
        return [
            origin for origin in (o.strip() for o in self.api_cors_origins.split(",")) if origin
        ]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.env is Environment.production

    @property
    def database_url(self) -> URL:
        """Async SQLAlchemy URL. Built via ``URL.create`` so credentials are escaped correctly."""
        return URL.create(
            drivername="postgresql+asyncpg",
            username=self.postgres_app_user,
            password=self.postgres_app_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/0"

    def secret_values(self) -> frozenset[str]:
        """Literal secret values, used by the log scrubber to guarantee they never appear."""
        values = {
            self.secret_key.get_secret_value(),
            self.postgres_app_password.get_secret_value(),
            self.postgres_migrator_password.get_secret_value(),
            self.redis_password.get_secret_value(),
        }
        return frozenset(v for v in values if len(v) >= 8)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
