"""Structured JSON logging with correlation IDs and defensive output handling.

Three protections live here:

1. **Secret scrubbing.** Literal secret values from settings are replaced with
   ``***REDACTED***`` in every emitted record, and fields whose *name* looks sensitive
   are redacted by key. (THREAT_MODEL T-3.3 groundwork, T-5.4.)
2. **Untrusted-content neutralisation.** ``safe_value`` strips every C0/C1 control
   character except tab — including LF and CR — and caps length, so log-injection attempts
   in ingested data cannot forge log lines or emit terminal escape sequences.
   (THREAT_MODEL T-1.1.)
3. **No interpolation of untrusted data into messages.** Callers pass untrusted values as
   structured ``extra`` fields, never inside the format string.

Full EVE field sanitisation for persistence is a separate concern and lives in
``aegisnet.domain.eve.sanitize``, which restates the rule rather than importing it.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, Final

REDACTED: Final = "***REDACTED***"
MAX_VALUE_CHARS: Final = 512

# Every C0 and C1 control character except tab (0x09). LF and CR are stripped
# deliberately: the log format is one JSON object per line, so a literal newline inside a
# value is the primary log-forging primitive. json.dumps would escape it, but relying on
# the formatter alone would reintroduce the flaw for any future non-JSON sink.
_CONTROL_CHARS: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")
_SENSITIVE_KEY: Final = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie|credential)", re.IGNORECASE
)

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

_RESERVED: Final = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


def untrusted_text(value: str, *, max_chars: int = MAX_VALUE_CHARS) -> str:
    """Neutralise one untrusted string at the point it leaves the request.

    CR and LF are removed first and explicitly, then every other control character except
    tab, then the result is truncated. The formatter applies the same treatment to every
    record, so a log line is clean regardless of the caller; this function exists for the
    call sites that hand request-derived text to a log call or a response header, so that
    the guard is visible at the sink itself, to a reader and to static taint analysis,
    rather than implied by the formatter downstream.
    """
    cleaned = value.replace("\r", "").replace("\n", "")
    cleaned = _CONTROL_CHARS.sub("", cleaned)
    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + "…[truncated]"
    return cleaned


def safe_value(value: object, *, max_chars: int = MAX_VALUE_CHARS) -> object:
    """Neutralise untrusted content for logging.

    Strings have every control character except tab removed, and are truncated. Containers
    are handled recursively. Non-string scalars pass through unchanged.
    """
    if isinstance(value, str):
        return untrusted_text(value, max_chars=max_chars)
    if isinstance(value, dict):
        return {
            str(safe_value(k, max_chars=64)): safe_value(v, max_chars=max_chars)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [safe_value(v, max_chars=max_chars) for v in value]
    return value


class SecretScrubber(logging.Filter):
    """Replaces literal secret values and sensitive-looking fields with a placeholder."""

    def __init__(self, secrets: frozenset[str] | None = None) -> None:
        super().__init__()
        self._secrets = frozenset(secrets or ())

    def scrub_text(self, text: str) -> str:
        for secret in self._secrets:
            if secret and secret in text:
                text = text.replace(secret, REDACTED)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        # Name and signature are fixed by the logging.Filter API.
        record.msg = self.scrub_text(str(record.msg))
        for key in list(vars(record)):
            if key in _RESERVED:
                continue
            if _SENSITIVE_KEY.search(key):
                setattr(record, key, REDACTED)
        return True


class JsonFormatter(logging.Formatter):
    """Emits one JSON object per record. No secret, no raw untrusted text."""

    def __init__(self, scrubber: SecretScrubber) -> None:
        super().__init__()
        self._scrubber = scrubber

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": safe_value(record.getMessage()),
        }
        cid = correlation_id_var.get()
        if cid:
            payload["correlation_id"] = cid

        for key, value in vars(record).items():
            if key in _RESERVED or key.startswith("_") or key in payload:
                continue
            payload[key] = safe_value(value)

        if record.exc_info:
            # Exception type only. Tracebacks are useful locally but must not become a
            # structured field that could be forwarded anywhere. Uvicorn still prints the
            # traceback to stderr in development.
            exc_type = record.exc_info[0]
            payload["exception"] = exc_type.__name__ if exc_type else "UnknownException"

        return self._scrubber.scrub_text(json.dumps(payload, default=str, ensure_ascii=False))


def configure_logging(level: str = "INFO", secrets: frozenset[str] | None = None) -> None:
    """Install the JSON handler on the root logger. Idempotent."""
    scrubber = SecretScrubber(secrets)
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter(scrubber))
    handler.addFilter(scrubber)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn's own handlers would otherwise emit unstructured lines alongside ours.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
