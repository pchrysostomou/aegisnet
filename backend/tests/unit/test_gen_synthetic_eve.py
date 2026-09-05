"""The synthetic generator is deterministic, safe by construction, and schema-faithful."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

from aegisnet.domain.eve.normalizer import normalize_line
from aegisnet.domain.models import NormalizedEvent
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

GENERATOR = REPO_ROOT / "tools" / "gen_synthetic_eve.py"
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
ALLOWED_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
]
ALLOWED_NAME_SUFFIXES = (".example.test", ".example.com", "example.test", "example.com")


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_synthetic_eve", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _moment(text: str) -> datetime:
    """A Suricata timestamp as an instant; the generator writes `+0000` without a colon."""
    return datetime.fromisoformat(text.replace("+0000", "+00:00"))


def _run(tmp_path: Path, name: str, *args: str) -> tuple[bytes, dict[str, object]]:
    module = _load_generator()
    out = tmp_path / f"{name}.ndjson"
    assert module.main(["--out", str(out), "--events", "300", *args]) == 0
    manifest = json.loads(out.with_suffix("").with_suffix(".manifest.json").read_text())
    return out.read_bytes(), manifest


def test_same_seed_is_byte_identical_and_a_different_seed_is_not(tmp_path: Path) -> None:
    first, _ = _run(tmp_path, "a", "--seed", "7")
    second, _ = _run(tmp_path, "b", "--seed", "7")
    other, _ = _run(tmp_path, "c", "--seed", "8")
    assert first == second
    assert first != other


def test_manifest_counts_and_checksum_describe_the_file(tmp_path: Path) -> None:
    payload, manifest = _run(tmp_path, "m", "--seed", "7")
    lines = payload.decode("ascii").splitlines()
    counted = Counter(json.loads(line)["event_type"] for line in lines)
    assert manifest["events"] == len(lines) == 300
    assert manifest["counts_by_type"] == dict(sorted(counted.items()))
    assert manifest["size_bytes"] == len(payload)
    import hashlib

    assert manifest["sha256"] == hashlib.sha256(payload).hexdigest()


def test_every_generated_line_normalises_with_unique_hashes(tmp_path: Path) -> None:
    payload, _ = _run(tmp_path, "n", "--seed", "7")
    events = [normalize_line(line, now=NOW) for line in payload.decode("ascii").splitlines()]
    assert all(isinstance(event, NormalizedEvent) for event in events)
    hashes = {event.event_hash for event in events if isinstance(event, NormalizedEvent)}
    assert len(hashes) == 300


def test_only_private_or_documentation_addresses_and_example_names_appear(tmp_path: Path) -> None:
    payload, _ = _run(tmp_path, "s", "--seed", "7")
    for line in payload.decode("ascii").splitlines():
        record = json.loads(line)
        for key in ("src_ip", "dest_ip"):
            address = ipaddress.ip_address(record[key])
            assert any(address in network for network in ALLOWED_NETWORKS), record[key]
        for name in _names(record):
            assert name.endswith(ALLOWED_NAME_SUFFIXES), name


def _names(record: dict[str, object]) -> list[str]:
    names: list[str] = []
    dns = record.get("dns")
    if isinstance(dns, dict) and isinstance(dns.get("rrname"), str):
        names.append(dns["rrname"])
    http = record.get("http")
    if isinstance(http, dict) and isinstance(http.get("hostname"), str):
        names.append(http["hostname"])
    tls = record.get("tls")
    if isinstance(tls, dict) and isinstance(tls.get("sni"), str):
        names.append(tls["sni"])
    return names


def test_timestamps_are_monotonic_and_in_suricata_format(tmp_path: Path) -> None:
    payload, manifest = _run(tmp_path, "t", "--seed", "7", "--start", "2026-09-01T00:00:00Z")
    stamps = [json.loads(line)["timestamp"] for line in payload.decode("ascii").splitlines()]
    assert stamps == sorted(stamps)
    assert all(stamp.endswith("+0000") and len(stamp) == 31 for stamp in stamps)
    assert manifest["time_range"] == {"start": stamps[0], "end": stamps[-1]}


def test_generator_has_no_network_capability() -> None:
    source = GENERATOR.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import scapy",
        "from scapy",
        "import urllib",
        "import http",
        "import requests",
        "import asyncio",
        "os.system",
    ):
        assert forbidden not in source, forbidden


def test_a_flow_record_starts_before_it_is_emitted(tmp_path: Path) -> None:
    """ADR-022: `when` is the conversation, the record is stamped when Suricata emits it. The
    generator had this backwards until Chunk 14, and nothing here noticed for six chunks."""
    payload, manifest = _run(tmp_path, "flow", "--seed", "11")
    flows = [
        json.loads(line)
        for line in payload.decode().splitlines()
        if json.loads(line)["event_type"] == "flow"
    ]
    assert flows
    for record in flows:
        start = _moment(record["flow"]["start"])
        emitted = _moment(record["timestamp"])
        assert start <= emitted, "a flow cannot be emitted before it began"
        assert (emitted - start).total_seconds() == record["flow"]["age"]
    assert manifest["generator_version"] == 2, "the version says which semantics these are"


def test_dns_is_written_in_both_eve_shapes(tmp_path: Path) -> None:
    """A fleet runs more than one Suricata version, and the two shapes differ in the way that
    blinded D-003: v3 puts an `rcode` on the request as well (ADR-022)."""
    payload, _ = _run(tmp_path, "dns", "--seed", "13", "--events", "600")
    dns = [
        json.loads(line)["dns"]
        for line in payload.decode().splitlines()
        if json.loads(line)["event_type"] == "dns"
    ]
    shapes = {(record["version"], record["type"]) for record in dns}
    assert shapes == {(3, "request"), (3, "response"), (2, "query"), (2, "answer")}
    for record in dns:
        if record["type"] == "request":
            assert "rcode" in record, "v3 puts one on both halves"
        if record["type"] == "query":
            assert "rcode" not in record, "v2 puts one only on the answer"
