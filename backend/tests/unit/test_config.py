"""Settings behaviour that ADR-011 relies on."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegisnet.config import PLACEHOLDER_MARKER, Environment, Settings, get_settings
from tests.conftest import make_settings

pytestmark = pytest.mark.unit

REAL = "not-a-placeholder-0123456789"
SECRET_NAMES = (
    "SECRET_KEY",
    "POSTGRES_APP_PASSWORD",
    "POSTGRES_MIGRATOR_PASSWORD",
    "REDIS_PASSWORD",
)


@pytest.mark.usefixtures("no_secret_env")
@pytest.mark.parametrize("env", [Environment.development, Environment.production])
def test_placeholder_secrets_are_refused_outside_test(env: Environment) -> None:
    with pytest.raises(ValidationError) as excinfo:
        make_settings(env=env)
    message = str(excinfo.value)
    assert "make bootstrap" in message
    for name in SECRET_NAMES:
        assert name in message


@pytest.mark.usefixtures("no_secret_env")
def test_refusal_names_only_the_offending_variables() -> None:
    with pytest.raises(ValidationError) as excinfo:
        make_settings(
            env=Environment.development,
            secret_key=REAL,
            postgres_app_password=REAL,
            postgres_migrator_password=REAL,
        )
    message = str(excinfo.value)
    assert "REDIS_PASSWORD" in message
    assert "SECRET_KEY" not in message


@pytest.mark.usefixtures("no_secret_env")
def test_test_environment_tolerates_placeholders() -> None:
    settings = make_settings(env=Environment.test)
    assert PLACEHOLDER_MARKER in settings.secret_key.get_secret_value()


@pytest.mark.usefixtures("no_secret_env")
def test_real_secrets_are_accepted_outside_test() -> None:
    settings = make_settings(
        env=Environment.development,
        secret_key=REAL,
        postgres_app_password=REAL,
        postgres_migrator_password=REAL,
        redis_password=REAL,
    )
    assert settings.env is Environment.development
    assert settings.is_production is False


@pytest.mark.usefixtures("no_secret_env")
def test_debug_is_forbidden_in_production() -> None:
    with pytest.raises(ValidationError, match="DEBUG"):
        make_settings(
            env=Environment.production,
            debug=True,
            secret_key=REAL,
            postgres_app_password=REAL,
            postgres_migrator_password=REAL,
            redis_password=REAL,
        )


def test_secrets_never_appear_in_repr() -> None:
    settings = make_settings(secret_key=REAL, redis_password=REAL)
    assert REAL not in repr(settings)
    assert REAL not in str(settings)
    assert REAL not in settings.model_dump_json()


def test_cors_origins_are_split_and_trimmed() -> None:
    settings = make_settings(api_cors_origins=" http://127.0.0.1:3000 , ,http://localhost:3000,")
    assert settings.cors_origin_list == ["http://127.0.0.1:3000", "http://localhost:3000"]


def test_database_url_uses_asyncpg_and_escapes_credentials() -> None:
    settings = make_settings(postgres_app_password="p@ss:w/rd#1234")
    url = settings.database_url
    assert url.drivername == "postgresql+asyncpg"
    assert url.username == "aegisnet_app"
    assert url.password == "p@ss:w/rd#1234"
    rendered = url.render_as_string(hide_password=False)
    assert "p%40ss%3Aw%2Frd%231234" in rendered
    # The default rendering (what would reach a log line) hides the password.
    assert "p@ss" not in str(url)
    assert "1234" not in str(url)


def test_redis_url_carries_no_credential() -> None:
    # Host and port are explicit: the test-runner container points REDIS_HOST at an
    # unresolvable name on purpose, and the assertion must not depend on that.
    settings = make_settings(redis_host="redis", redis_port=6379, redis_password=REAL)
    assert settings.redis_url == "redis://redis:6379/0"
    assert REAL not in settings.redis_url


def test_secret_values_skips_short_strings() -> None:
    settings = make_settings(secret_key="short", redis_password=REAL)
    values = settings.secret_values()
    assert REAL in values
    assert "short" not in values


def test_probe_timeout_is_bounded() -> None:
    with pytest.raises(ValidationError):
        make_settings(probe_timeout_seconds=0)
    with pytest.raises(ValidationError):
        make_settings(probe_timeout_seconds=31)


def test_get_settings_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENV", "test")
    get_settings.cache_clear()
    try:
        assert get_settings() is get_settings()
        assert isinstance(get_settings(), Settings)
    finally:
        get_settings.cache_clear()
