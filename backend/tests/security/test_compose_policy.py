"""T-5.1 / T-5.2 / T-5.4: the committed Compose manifests declare a loopback-only, hardened stack.

These tests read the manifests as data. They prove what the files declare, not what a
running stack does.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

COMPOSE = REPO_ROOT / "docker-compose.yml"
TEST_COMPOSE = REPO_ROOT / "docker-compose.test.yml"
OVERRIDE_EXAMPLE = REPO_ROOT / "docker-compose.override.yml.example"
# The opt-in lab manifest (ADR-021) is held to the rules that are true of every manifest in
# the repository: loopback-only ports, no host namespace, no Docker socket, no secret
# literal. What is specific to the lab — the internal network, the one capability the
# sensor adds back, IDS-only — lives in test_lab_policy.py.
LAB_COMPOSE = REPO_ROOT / "infra" / "lab" / "docker-compose.lab.yml"
ALL_MANIFESTS = [COMPOSE, TEST_COMPOSE, OVERRIDE_EXAMPLE, LAB_COMPOSE]

LOOPBACK_PORT = re.compile(r"^127\.0\.0\.1:\d{2,5}:\d{2,5}$")
SECRET_KEY_NAME = re.compile(r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY)", re.IGNORECASE)
INTERPOLATION = re.compile(r"^\$\{[A-Z0-9_]+(:-[^}]*)?\}$")


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _services(path: Path) -> dict[str, dict[str, Any]]:
    services = _load(path).get("services", {})
    assert isinstance(services, dict)
    return services


def _environment(service: dict[str, Any]) -> dict[str, str]:
    env = service.get("environment", {})
    if isinstance(env, list):
        return dict(item.split("=", 1) for item in env)
    return {str(k): str(v) for k, v in env.items()}


@pytest.mark.parametrize("path", ALL_MANIFESTS, ids=lambda p: p.name)
def test_every_published_port_binds_to_loopback(path: Path) -> None:
    for name, service in _services(path).items():
        for entry in service.get("ports", []):
            assert LOOPBACK_PORT.match(str(entry)), f"{path.name}:{name} publishes {entry!r}"


def test_datastores_worker_and_scheduler_publish_no_port() -> None:
    services = _services(COMPOSE)
    for name in ("db", "redis", "worker", "scheduler"):
        assert "ports" not in services[name], f"{name} must not publish a host port"
        assert "expose" not in services[name]


@pytest.mark.parametrize("path", [COMPOSE, TEST_COMPOSE], ids=lambda p: p.name)
def test_every_service_drops_all_capabilities_and_privilege_escalation(path: Path) -> None:
    for name, service in _services(path).items():
        assert service.get("cap_drop") == ["ALL"], f"{path.name}:{name}"
        assert "no-new-privileges:true" in service.get("security_opt", []), f"{path.name}:{name}"
        assert not service.get("privileged"), f"{path.name}:{name}"
        assert not service.get("cap_add"), f"{path.name}:{name}"


@pytest.mark.parametrize("path", ALL_MANIFESTS, ids=lambda p: p.name)
def test_no_host_namespace_or_docker_socket(path: Path) -> None:
    for name, service in _services(path).items():
        for key in ("network_mode", "pid", "ipc"):
            assert service.get(key) != "host", f"{path.name}:{name} uses host {key}"
        for volume in service.get("volumes", []):
            assert "docker.sock" not in str(volume), f"{path.name}:{name} mounts the Docker socket"


@pytest.mark.parametrize("path", ALL_MANIFESTS, ids=lambda p: p.name)
def test_no_inline_secret_literals(path: Path) -> None:
    """Closes the gap recorded in CHANGELOG: the test runner manifest is covered too."""
    for name, service in _services(path).items():
        for key, value in _environment(service).items():
            if SECRET_KEY_NAME.search(key):
                assert INTERPOLATION.match(value), f"{path.name}:{name} sets {key} to a literal"
        for token in service.get("command", []) if isinstance(service.get("command"), list) else []:
            if SECRET_KEY_NAME.search(str(token)) and "=" in str(token):
                _, _, value = str(token).partition("=")
                assert INTERPOLATION.match(value), f"{path.name}:{name} command carries a literal"


def test_redis_requires_a_password_from_the_environment() -> None:
    command = _services(COMPOSE)["redis"]["command"]
    assert "--requirepass" in command
    assert command[command.index("--requirepass") + 1] == "${REDIS_PASSWORD}"


def test_api_and_web_start_only_after_their_dependencies_are_healthy() -> None:
    services = _services(COMPOSE)
    assert services["api"]["depends_on"] == {
        "db": {"condition": "service_healthy"},
        "redis": {"condition": "service_healthy"},
    }
    assert services["web"]["depends_on"] == {"api": {"condition": "service_healthy"}}
    assert services["worker"]["depends_on"] == {
        "db": {"condition": "service_healthy"},
        "redis": {"condition": "service_healthy"},
    }


def test_samples_are_mounted_read_only_and_nowhere_else() -> None:
    """T-1.6: the only dataset source is ./samples, read-only, in the two services that ingest."""
    services = _services(COMPOSE)
    for name in ("api", "worker"):
        assert "./samples:/app/samples:ro" in services[name]["volumes"], name
        assert _environment(services[name])["SAMPLES_DIR"] == "/app/samples", name
    for name in ("db", "redis", "web"):
        assert not any("samples" in str(v) for v in services[name].get("volumes", [])), name


def test_every_service_declares_a_healthcheck() -> None:
    for name, service in _services(COMPOSE).items():
        assert "healthcheck" in service, name
        assert service["healthcheck"].get("test"), name


def test_worker_liveness_probe_cannot_match_its_own_shell() -> None:
    """Regression: `pgrep -f 'dramatiq ...'` matched the sh -c wrapper and always passed."""
    test = _services(COMPOSE)["worker"]["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL"
    assert "pgrep -f '[d]ramatiq aegisnet.workers.main'" in test[1]


def test_worker_runs_the_dedicated_entrypoint_module() -> None:
    command = _services(COMPOSE)["worker"]["command"]
    assert command[:2] == ["dramatiq", "aegisnet.workers.main"]


def test_scheduler_runs_periodiq_against_the_same_entrypoint_and_mounts_nothing() -> None:
    """ADR-020: the scheduler only sends; it needs Redis, no volume, no database."""
    scheduler = _services(COMPOSE)["scheduler"]
    assert scheduler["command"] == ["periodiq", "aegisnet.workers.main"]
    assert "volumes" not in scheduler and "ports" not in scheduler
    assert scheduler["depends_on"] == {"redis": {"condition": "service_healthy"}}
    test = scheduler["healthcheck"]["test"]
    assert test[0] == "CMD-SHELL"
    assert "pgrep -f '[p]eriodiq aegisnet.workers.main'" in test[1]


def test_test_runner_has_no_secrets_and_cannot_reach_a_datastore() -> None:
    env = _environment(_services(TEST_COMPOSE)["tests"])
    assert env["ENV"] == "test"
    assert not any(SECRET_KEY_NAME.search(key) for key in env)
    assert env["POSTGRES_HOST"].endswith("-unused")
    assert env["REDIS_HOST"].endswith("-unused")
    assert "env_file" not in _services(TEST_COMPOSE)["tests"]


def test_ephemeral_test_database_is_opt_in_hardened_and_unpublished() -> None:
    """F-2: the database suite's PostgreSQL mirrors the real db and leaves nothing behind."""
    services = _services(TEST_COMPOSE)
    db = services["db-test"]
    assert db["profiles"] == ["db"]
    assert db["image"] == services_main()["db"]["image"]
    assert db.get("user") == "postgres"
    assert "ports" not in db and "expose" not in db
    assert db["volumes"] == ["./infra/postgres/init:/docker-entrypoint-initdb.d:ro"]
    assert "healthcheck" in db
    for key, value in _environment(db).items():
        assert INTERPOLATION.match(value), f"db-test sets {key} to a literal"


def test_database_suite_runner_targets_only_the_ephemeral_database() -> None:
    runner = _services(TEST_COMPOSE)["tests-db"]
    env = _environment(runner)
    assert runner["profiles"] == ["db"]
    assert runner["depends_on"] == {"db-test": {"condition": "service_healthy"}}
    assert env["ENV"] == "test"
    assert env["AEGISNET_DB_TESTS"] == "1"
    assert env["POSTGRES_HOST"] == "db-test"
    assert env["REDIS_HOST"].endswith("-unused")
    assert runner["command"][:3] == ["pytest", "-m", "db"]
    assert not any(SECRET_KEY_NAME.search(key) for key in env)


def services_main() -> dict[str, dict[str, Any]]:
    return _services(COMPOSE)


def test_postgres_init_scripts_are_mounted_read_only() -> None:
    volumes = _services(COMPOSE)["db"]["volumes"]
    init = [v for v in volumes if "docker-entrypoint-initdb.d" in str(v)]
    assert init == ["./infra/postgres/init:/docker-entrypoint-initdb.d:ro"]


def test_official_images_are_started_as_their_service_user() -> None:
    """Regression: postgres/redis entrypoints start as root and drop privileges with
    gosu/setpriv, which needs CAP_SETUID and fails under cap_drop ALL. Declaring the
    service user up front means no privilege switch is attempted."""
    services = _services(COMPOSE)
    assert services["db"].get("user") == "postgres"
    assert services["redis"].get("user") == "redis"


def test_the_upload_spool_is_a_named_volume_shared_by_api_and_worker_only() -> None:
    """T-1.4 / TB-5: uploads wait in a private named volume; a message carries only the
    spool name, and only the two services that need the bytes can reach them."""
    services = _services(COMPOSE)
    for name in ("api", "worker"):
        assert "ingest_spool:/app/spool" in services[name]["volumes"], name
        assert _environment(services[name])["SPOOL_DIR"] == "/app/spool", name
    for name, service in services.items():
        if name not in ("api", "worker"):
            assert not any("spool" in str(v) for v in service.get("volumes", [])), name
    assert "ingest_spool" in _load(COMPOSE)["volumes"]
    assert not any(
        "spool" in str(v) for s in _services(TEST_COMPOSE).values() for v in s.get("volumes", [])
    )
