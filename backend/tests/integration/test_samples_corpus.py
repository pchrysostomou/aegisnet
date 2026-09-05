"""The committed synthetic corpus, its manifest and the registry agree with each other and
with the normaliser. This is the integrity check `make gen-synthetic` tells you about."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import Counter
from datetime import UTC, datetime

import pytest

from aegisnet.adapters.files.registry import load_registry, resolve_dataset
from aegisnet.domain.eve.normalizer import normalize_line
from aegisnet.domain.models import NormalizedEvent
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.integration

SAMPLES = REPO_ROOT / "samples"
DATASET_ID = "synthetic-benign-baseline-01"
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
ALLOWED_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


@pytest.fixture(scope="module")
def corpus_lines() -> list[str]:
    registry = load_registry(SAMPLES)
    resolved = resolve_dataset(SAMPLES, registry, DATASET_ID)  # verifies the sha256
    return resolved.path.read_text(encoding="ascii").splitlines()


def test_registry_entry_and_manifest_match_the_file(corpus_lines: list[str]) -> None:
    entry = load_registry(SAMPLES).get(DATASET_ID)
    assert entry.manifest is not None
    manifest = json.loads((SAMPLES / entry.manifest).read_text(encoding="utf-8"))
    payload = (SAMPLES / entry.path).read_bytes()
    assert manifest["sha256"] == entry.sha256 == hashlib.sha256(payload).hexdigest()
    assert manifest["events"] == len(corpus_lines)
    assert manifest["generator"] == "tools/gen_synthetic_eve.py"
    assert entry.licence.startswith("MIT")


def test_every_line_normalises_and_the_counts_match_the_manifest(corpus_lines: list[str]) -> None:
    entry = load_registry(SAMPLES).get(DATASET_ID)
    assert entry.manifest is not None
    manifest = json.loads((SAMPLES / entry.manifest).read_text(encoding="utf-8"))
    outcomes = [normalize_line(line, now=NOW) for line in corpus_lines]
    events = [outcome for outcome in outcomes if isinstance(outcome, NormalizedEvent)]
    assert len(events) == len(corpus_lines), "the corpus must contain no rejectable line"
    counts = Counter(event.event_type.value for event in events)
    assert dict(sorted(counts.items())) == manifest["counts_by_type"]
    assert len({event.event_hash for event in events}) == len(events), "hashes must be unique"


def test_corpus_uses_only_lab_and_documentation_addresses(corpus_lines: list[str]) -> None:
    for line in corpus_lines:
        record = json.loads(line)
        for key in ("src_ip", "dest_ip"):
            address = ipaddress.ip_address(record[key])
            assert any(address in network for network in ALLOWED_NETWORKS), record[key]


def test_corpus_is_small_enough_to_commit(corpus_lines: list[str]) -> None:
    entry = load_registry(SAMPLES).get(DATASET_ID)
    assert (SAMPLES / entry.path).stat().st_size < 2 * 1024 * 1024
