"""Enumerations shared by the schema and, from Chunk 3, by the EVE normaliser.

Each member's name equals its value, and the values are the PostgreSQL enum labels that
the baseline migration creates (``docs/data-model.md``). Adding a label is a schema change
and therefore ships with an Alembic revision.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class SourceType(StrEnum):
    suricata_eve = "suricata_eve"


@unique
class IngestMethod(StrEnum):
    api_ndjson = "api_ndjson"
    api_file = "api_file"
    registry_import = "registry_import"


@unique
class IngestStatus(StrEnum):
    received = "received"
    normalizing = "normalizing"
    complete = "complete"
    failed = "failed"


@unique
class EventType(StrEnum):
    alert = "alert"
    dns = "dns"
    http = "http"
    flow = "flow"
    tls = "tls"
    fileinfo = "fileinfo"
    anomaly = "anomaly"
    ssh = "ssh"
    other = "other"


@unique
class RejectReason(StrEnum):
    json_parse = "json_parse"
    schema_invalid = "schema_invalid"
    missing_required = "missing_required"
    timestamp_out_of_range = "timestamp_out_of_range"
    too_large = "too_large"
    too_deep = "too_deep"
    unsupported_event_type = "unsupported_event_type"


@unique
class AssetEnvironment(StrEnum):
    lab = "lab"
    dev = "dev"
    staging = "staging"
    prod_sim = "prod_sim"


@unique
class UserRole(StrEnum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


@unique
class ServiceTokenRole(StrEnum):
    ingest_service = "ingest_service"


@unique
class AuditResult(StrEnum):
    success = "success"
    denied = "denied"
    error = "error"


# ---------------------------------------------------------------- detection (M2)


@unique
class EntityType(StrEnum):
    """What an alert is about; the correlation key type (``alerts.entity_type``)."""

    asset = "asset"
    src_ip = "src_ip"
    dest_ip = "dest_ip"
    domain = "domain"


@unique
class SampleRole(StrEnum):
    """Why a contributing event was kept as a sample (``alert_events.role``)."""

    first = "first"
    last = "last"
    peak = "peak"
    sample = "sample"


@unique
class AlertAssetRole(StrEnum):
    source = "source"
    destination = "destination"


@unique
class DetectorRunStatus(StrEnum):
    success = "success"
    error = "error"
    skipped = "skipped"


@unique
class AlertStatus(StrEnum):
    open = "open"
    correlated = "correlated"
    suppressed = "suppressed"


@unique
class BaselineMetric(StrEnum):
    outbound_bytes_per_hour = "outbound_bytes_per_hour"
    distinct_dest_per_hour = "distinct_dest_per_hour"
    dns_queries_per_hour = "dns_queries_per_hour"


@unique
class IncidentStatus(StrEnum):
    """Where a case is. Three closed states because *why* a case closed is the part an analyst
    needs later, and a single `closed` would throw it away. The legal moves between them are
    in `domain/incidents.py`, which is where the workflow lives."""

    new = "new"
    triaging = "triaging"
    investigating = "investigating"
    contained_recommended = "contained_recommended"
    closed_true_positive = "closed_true_positive"
    closed_false_positive = "closed_false_positive"
    closed_benign = "closed_benign"


@unique
class TimelineEntryType(StrEnum):
    """What a line in an incident's story can be. The timeline is append-only, so this is the
    whole grammar of what a case can say about itself."""

    alert_fired = "alert_fired"
    observation = "observation"
    status_change = "status_change"
    note_added = "note_added"
    brief_generated = "brief_generated"
    report_exported = "report_exported"
    asset_linked = "asset_linked"


@unique
class IncidentAlertSource(StrEnum):
    """Who put an alert in a case. A rule's arithmetic and an analyst's judgement are both
    legitimate, and telling them apart later matters more than either."""

    correlation_engine = "correlation_engine"
    analyst = "analyst"
