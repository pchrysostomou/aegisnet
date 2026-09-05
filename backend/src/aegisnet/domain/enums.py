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
