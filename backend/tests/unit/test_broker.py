"""Broker factory: authenticated client, declares no actors itself, no import-time side effects."""

from __future__ import annotations

import dramatiq
import pytest

from aegisnet.adapters.queue import broker as broker_module
from tests.conftest import make_settings

pytestmark = pytest.mark.unit

PASSWORD = "redis-password-for-tests-0123456789"


def test_client_is_authenticated_from_settings() -> None:
    """Regression: RedisBroker(url=..., password=...) silently dropped the password."""
    settings = make_settings(redis_host="cache.internal", redis_port=6380, redis_password=PASSWORD)
    broker = broker_module.build_broker(settings)
    kwargs = broker.client.connection_pool.connection_kwargs
    assert kwargs["password"] == PASSWORD
    assert kwargs["host"] == "cache.internal"
    assert kwargs["port"] == 6380
    assert kwargs["db"] == 0


def test_the_factory_declares_no_actors() -> None:
    """Actors bind to the broker that workers.main installs, never to a fresh factory product."""
    broker = broker_module.build_broker(make_settings())
    assert broker.get_declared_actors() == set()
    assert broker.get_declared_queues() == set()


def test_install_sets_the_process_default() -> None:
    previous = dramatiq.get_broker()
    try:
        broker = broker_module.install(make_settings())
        assert dramatiq.get_broker() is broker
    finally:
        dramatiq.set_broker(previous)


def test_factory_module_has_no_import_side_effects() -> None:
    assert not hasattr(broker_module, "broker"), "boot logic belongs in workers/main.py"
