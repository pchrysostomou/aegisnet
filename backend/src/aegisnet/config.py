"""Application configuration.

Every secret is a ``SecretStr`` so it cannot be printed by accident. The settings
object refuses to load when any secret still holds a ``.env.example`` placeholder and
the environment is not ``test`` — this is what makes ``make bootstrap`` mandatory
rather than optional (decision F-1 / ADR-011).
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
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

    # ---- datasets and ingest (docs/api-milestone-1.md; THREAT_MODEL T-1.4, T-1.5, T-1.7)
    samples_dir: Path = Path("samples")
    ingest_max_body_bytes: Annotated[int, Field(ge=1024)] = 50 * 1024 * 1024
    ingest_max_lines: Annotated[int, Field(ge=1)] = 200_000
    ingest_max_line_bytes: Annotated[int, Field(ge=256)] = 64 * 1024
    ingest_max_json_depth: Annotated[int, Field(ge=2, le=64)] = 12
    ingest_max_keys_per_object: Annotated[int, Field(ge=8)] = 200
    ingest_timestamp_max_past_days: Annotated[int, Field(ge=1)] = 3650
    ingest_timestamp_max_future_hours: Annotated[int, Field(ge=0)] = 24
    ingest_sync_max_lines: Annotated[int, Field(ge=1)] = 1000
    spool_dir: Path = Path("spool")

    # ---- authentication and rate limits (docs/api-milestone-1.md; T-2.1, T-2.4; ADR-016)
    jwt_issuer: str = "aegisnet"
    access_ttl_seconds: Annotated[int, Field(ge=60, le=3600)] = 900
    refresh_ttl_days: Annotated[int, Field(ge=1, le=90)] = 14
    login_max_failures: Annotated[int, Field(ge=1)] = 5
    login_lockout_minutes: Annotated[int, Field(ge=1)] = 15
    cookie_secure: bool = True
    rate_limit_login_per_15min: Annotated[int, Field(ge=1)] = 5
    rate_limit_ingest_per_min: Annotated[int, Field(ge=1)] = 30
    rate_limit_ingest_bytes_per_hour: Annotated[int, Field(ge=1024)] = 200 * 1024 * 1024
    rate_limit_read_per_min: Annotated[int, Field(ge=1)] = 120
    rate_limit_default_per_min: Annotated[int, Field(ge=1)] = 60

    # ---- schedule and post-ingest sweeps (ADR-020)
    # The scheduler fires a sweep every SWEEP_CADENCE_MINUTES (must divide 60 so the ticks
    # sit on a fixed grid) over the last SWEEP_LOOKBACK_MINUTES; late-arriving events are
    # picked up by the overlap, duplicates are absorbed by the alert dedup key.
    sweep_cadence_minutes: Annotated[int, Field(ge=1, le=60)] = 10
    sweep_lookback_minutes: Annotated[int, Field(ge=10, le=1440)] = 60
    # The nightly baseline recompute: hour on the scheduler's clock (UTC in the image).
    baseline_recompute_hour: Annotated[int, Field(ge=0, le=23)] = 2
    baseline_window_days: Annotated[int, Field(ge=1, le=90)] = 7
    # A scheduled message older than this when a worker picks it up is skipped, so a
    # worker that was down does not replay a backlog of stale ticks.
    schedule_skip_delay_seconds: Annotated[int, Field(ge=30, le=3600)] = 300
    # Queue a sweep over a batch's event-time span as soon as the batch completes.
    post_ingest_sweep: bool = True

    @field_validator("sweep_cadence_minutes")
    @classmethod
    def _cadence_divides_the_hour(cls, value: int) -> int:
        if 60 % value:
            raise ValueError("SWEEP_CADENCE_MINUTES must divide 60")
        return value

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
    def migration_url(self) -> URL:
        """Async SQLAlchemy URL for the migrator role, used only by Alembic (T-5.3)."""
        return URL.create(
            drivername="postgresql+asyncpg",
            username=self.postgres_migrator_user,
            password=self.postgres_migrator_password.get_secret_value(),
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
