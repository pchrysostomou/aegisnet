"""Ingest use-case against an in-memory store: counts, chunking, idempotency, limits."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aegisnet.adapters.files.registry import ChecksumMismatchError, DatasetNotFoundError
from aegisnet.domain.enums import IngestMethod, IngestStatus, RejectReason, SourceType
from aegisnet.domain.models import NormalizedEvent
from aegisnet.domain.ports import BatchCounts, BatchProvenance, BatchSummary, RejectedLine
from aegisnet.services.ingest_service import (
    IngestLimitExceededError,
    IngestLimits,
    IngestService,
    limits_from_settings,
)
from tests.conftest import REPO_ROOT, make_settings

pytestmark = pytest.mark.unit

FIXTURES = REPO_ROOT / "backend" / "tests" / "fixtures" / "eve"
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
PROVENANCE = BatchProvenance(
    source_type=SourceType.suricata_eve,
    source_label="unit",
    ingest_method=IngestMethod.api_ndjson,
)


class FakeStore:
    """The IngestStore port, in memory, with a call log for chunking assertions."""

    def __init__(self) -> None:
        self.batches: dict[UUID, dict[str, object]] = {}
        self.events: dict[bytes, tuple[UUID, NormalizedEvent, datetime]] = {}
        self.rejects: list[tuple[UUID, RejectedLine]] = []
        self.event_calls: list[int] = []
        self.fail_on_store = False

    async def open_batch(self, provenance: BatchProvenance, started_at: datetime) -> UUID:
        batch_id = uuid4()
        self.batches[batch_id] = {
            "provenance": provenance,
            "status": IngestStatus.received,
            "counts": BatchCounts(),
            "started_at": started_at,
            "finished_at": None,
        }
        return batch_id

    async def mark_normalizing(self, batch_id: UUID) -> None:
        self.batches[batch_id]["status"] = IngestStatus.normalizing

    async def store_events(
        self, batch_id: UUID, events: Sequence[NormalizedEvent], ingested_at: datetime
    ) -> int:
        if self.fail_on_store:
            raise RuntimeError("storage unavailable")
        self.event_calls.append(len(events))
        new = 0
        for event in events:
            if event.event_hash not in self.events:
                self.events[event.event_hash] = (batch_id, event, ingested_at)
                new += 1
        return new

    async def store_rejects(self, batch_id: UUID, rejects: Sequence[RejectedLine]) -> None:
        self.rejects.extend((batch_id, item) for item in rejects)

    async def finish_batch(
        self, batch_id: UUID, status: IngestStatus, counts: BatchCounts, finished_at: datetime
    ) -> None:
        self.batches[batch_id].update(status=status, counts=counts, finished_at=finished_at)

    async def get_batch(self, batch_id: UUID) -> BatchSummary | None:
        row = self.batches.get(batch_id)
        if row is None:
            return None
        provenance = row["provenance"]
        assert isinstance(provenance, BatchProvenance)
        counts = row["counts"]
        assert isinstance(counts, BatchCounts)
        status = row["status"]
        assert isinstance(status, IngestStatus)
        started = row["started_at"]
        assert isinstance(started, datetime)
        finished = row["finished_at"]
        assert finished is None or isinstance(finished, datetime)
        return BatchSummary(
            batch_id=batch_id,
            status=status,
            source_label=provenance.source_label,
            dataset_id=provenance.dataset_id,
            counts=counts,
            started_at=started,
            finished_at=finished,
        )


def _limits(max_lines: int = 200_000) -> IngestLimits:
    return limits_from_settings(make_settings(ingest_max_lines=max_lines))


def _service(store: FakeStore, **kwargs: object) -> IngestService:
    return IngestService(store, _limits(), clock=lambda: NOW, **kwargs)  # type: ignore[arg-type]


def _lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text(encoding="utf-8").splitlines()


async def test_benign_lines_are_all_stored_with_the_injected_clock() -> None:
    store = FakeStore()
    summary = await _service(store).ingest(_lines("benign.ndjson"), PROVENANCE)
    assert summary.status is IngestStatus.complete
    assert summary.counts == BatchCounts(received=11, stored=11, duplicate=0, rejected=0)
    assert summary.started_at == summary.finished_at == NOW
    assert {ingested for _, _, ingested in store.events.values()} == {NOW}
    assert summary.source_label == "unit" and summary.dataset_id is None


async def test_hostile_lines_become_rejects_with_line_numbers_and_the_batch_completes() -> None:
    store = FakeStore()
    summary = await _service(store).ingest(_lines("hostile.ndjson"), PROVENANCE)
    assert summary.status is IngestStatus.complete
    assert summary.counts == BatchCounts(received=12, stored=2, duplicate=0, rejected=10)
    assert [item.line_number for _, item in store.rejects] == list(range(3, 13))
    reasons = {item.reject.reason for _, item in store.rejects}
    assert reasons == {
        RejectReason.missing_required,
        RejectReason.schema_invalid,
        RejectReason.unsupported_event_type,
        RejectReason.json_parse,
        RejectReason.timestamp_out_of_range,
    }


async def test_re_ingest_stores_nothing_and_reports_every_line_as_duplicate() -> None:
    store = FakeStore()
    service = _service(store)
    await service.ingest(_lines("benign.ndjson"), PROVENANCE)
    again = await service.ingest(_lines("benign.ndjson"), PROVENANCE)
    assert again.counts == BatchCounts(received=11, stored=0, duplicate=11, rejected=0)
    assert len(store.events) == 11
    assert len(store.batches) == 2


async def test_duplicates_inside_one_batch_count_once_across_chunk_boundaries() -> None:
    store = FakeStore()
    line = _lines("benign.ndjson")[1]
    summary = await _service(store, chunk_size=2).ingest([line, line, line], PROVENANCE)
    assert summary.counts == BatchCounts(received=3, stored=1, duplicate=2, rejected=0)
    assert store.event_calls == [1, 1]  # each chunk deduplicated before it is written


async def test_events_are_written_in_chunks() -> None:
    store = FakeStore()
    await _service(store, chunk_size=4).ingest(_lines("benign.ndjson"), PROVENANCE)
    assert store.event_calls == [4, 4, 3]


async def test_blank_lines_are_skipped_and_bytes_are_decoded_leniently() -> None:
    store = FakeStore()
    lines: list[bytes | str] = ["", "   ", _lines("benign.ndjson")[0], b"\xff\xfe not json"]
    summary = await _service(store).ingest(lines, PROVENANCE)
    assert summary.counts == BatchCounts(received=2, stored=1, duplicate=0, rejected=1)
    ((_, rejected),) = store.rejects
    assert rejected.line_number == 4
    assert rejected.reject.reason is RejectReason.json_parse


async def test_the_line_budget_marks_the_batch_failed_and_keeps_what_was_stored() -> None:
    store = FakeStore()
    service = IngestService(store, _limits(max_lines=5), clock=lambda: NOW)
    with pytest.raises(IngestLimitExceededError, match="5-line limit"):
        await service.ingest(_lines("benign.ndjson"), PROVENANCE)
    (row,) = store.batches.values()
    assert row["status"] is IngestStatus.failed
    assert row["counts"] == BatchCounts(received=5, stored=5, duplicate=0, rejected=0)
    assert len(store.events) == 5


async def test_a_storage_failure_marks_the_batch_failed_and_propagates() -> None:
    store = FakeStore()
    store.fail_on_store = True
    with pytest.raises(RuntimeError, match="storage unavailable"):
        await _service(store).ingest(_lines("benign.ndjson"), PROVENANCE)
    (row,) = store.batches.values()
    assert row["status"] is IngestStatus.failed
    assert row["finished_at"] == NOW


async def test_a_pre_opened_batch_is_used_rather_than_a_new_one() -> None:
    store = FakeStore()
    service = _service(store)
    batch_id = await service.open_batch(PROVENANCE)
    summary = await service.ingest(_lines("benign.ndjson")[:3], PROVENANCE, batch_id=batch_id)
    assert summary.batch_id == batch_id
    assert len(store.batches) == 1


def _write_samples(tmp_path: Path, content: bytes, sha: str | None = None) -> Path:
    samples = tmp_path / "samples"
    (samples / "synthetic").mkdir(parents=True)
    (samples / "synthetic" / "small.ndjson").write_bytes(content)
    (samples / "registry.yml").write_text(
        "version: 1\n"
        "datasets:\n"
        "  - id: small-01\n"
        "    path: synthetic/small.ndjson\n"
        f"    sha256: {sha or hashlib.sha256(content).hexdigest()}\n"
        "    format: suricata_eve_ndjson\n"
        "    licence: CC-BY-4.0\n"
        "    citation: Example Lab (2026), synthetic corpus\n"
        "    description: three benign lines\n"
    )
    return samples


async def test_import_dataset_records_provenance_from_the_registry(tmp_path: Path) -> None:
    content = ("\n".join(_lines("benign.ndjson")[:3]) + "\n").encode()
    samples = _write_samples(tmp_path, content)
    store = FakeStore()
    summary = await _service(store).import_dataset(samples, "small-01", source_label="demo")
    assert summary.counts == BatchCounts(received=3, stored=3, duplicate=0, rejected=0)
    assert summary.dataset_id == "small-01"
    (row,) = store.batches.values()
    provenance = row["provenance"]
    assert isinstance(provenance, BatchProvenance)
    assert provenance.ingest_method is IngestMethod.registry_import
    assert provenance.dataset_licence == "CC-BY-4.0"
    assert provenance.dataset_citation == "Example Lab (2026), synthetic corpus"


async def test_import_of_an_unknown_dataset_opens_no_batch(tmp_path: Path) -> None:
    samples = _write_samples(tmp_path, b"{}\n")
    store = FakeStore()
    with pytest.raises(DatasetNotFoundError):
        await _service(store).import_dataset(samples, "missing", source_label="demo")
    assert store.batches == {}


async def test_import_failure_on_a_pre_opened_batch_marks_it_failed(tmp_path: Path) -> None:
    samples = _write_samples(tmp_path, b"{}\n", sha="a" * 64)
    store = FakeStore()
    service = _service(store)
    batch_id = await service.open_batch(PROVENANCE)
    with pytest.raises(ChecksumMismatchError):
        await service.import_dataset(samples, "small-01", source_label="demo", batch_id=batch_id)
    assert store.batches[batch_id]["status"] is IngestStatus.failed


def test_limits_come_from_settings() -> None:
    limits = limits_from_settings(
        make_settings(
            ingest_max_lines=7,
            ingest_max_line_bytes=1024,
            ingest_max_json_depth=5,
            ingest_max_keys_per_object=9,
            ingest_timestamp_max_past_days=2,
            ingest_timestamp_max_future_hours=1,
        )
    )
    assert limits.max_lines == 7
    assert (limits.parse.max_line_bytes, limits.parse.max_json_depth) == (1024, 5)
    assert limits.parse.max_keys_per_object == 9
    assert limits.window.max_past == timedelta(days=2)
    assert limits.window.max_future == timedelta(hours=1)


def test_chunk_size_must_be_positive() -> None:
    with pytest.raises(ValueError, match="chunk_size"):
        IngestService(FakeStore(), _limits(), chunk_size=0)
