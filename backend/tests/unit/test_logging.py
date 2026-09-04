"""Log hygiene: secret scrubbing and untrusted-content neutralisation (T-1.1, T-3.3, T-5.4)."""

from __future__ import annotations

import json
import logging

import pytest

from aegisnet.logging import (
    REDACTED,
    JsonFormatter,
    SecretScrubber,
    configure_logging,
    correlation_id_var,
    safe_value,
    untrusted_text,
)

pytestmark = pytest.mark.unit

SECRET = "sup3r-secret-value-that-must-not-leak"


def _format(record: logging.LogRecord, secrets: frozenset[str] = frozenset()) -> dict[str, object]:
    scrubber = SecretScrubber(secrets)
    scrubber.filter(record)
    line = JsonFormatter(scrubber).format(record)
    assert "\n" not in line, "one JSON object per line"
    parsed: dict[str, object] = json.loads(line)
    return parsed


def _record(msg: str, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, msg, None, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestSafeValue:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("plain", "plain"),
            ("a\x1b[31mred\x1b[0m", "a[31mred[0m"),
            ("line1\nline2\r\n", "line1line2"),
            ("nul\x00byte", "nulbyte"),
            ("c1\x85control\x9f", "c1control"),
            ("tab\tkept", "tab\tkept"),
            ("del\x7f", "del"),
        ],
    )
    def test_control_characters_are_stripped(self, raw: str, expected: str) -> None:
        assert safe_value(raw) == expected

    def test_long_values_are_truncated_with_a_marker(self) -> None:
        result = safe_value("x" * 600, max_chars=100)
        assert isinstance(result, str)
        assert result.startswith("x" * 100)
        assert result.endswith("[truncated]")
        assert len(result) < 600

    def test_containers_are_cleaned_recursively(self) -> None:
        result = safe_value({"k\n": ["v\r", ("w\x1b",)], "n": 3})
        assert result == {"k": ["v", ["w"]], "n": 3}

    def test_keys_are_capped_shorter_than_values(self) -> None:
        result = safe_value({"k" * 200: "v"})
        assert isinstance(result, dict)
        (key,) = result
        assert key.startswith("k" * 64)
        assert len(key) < 200

    def test_non_string_scalars_pass_through(self) -> None:
        assert safe_value(42) == 42
        assert safe_value(None) is None
        assert safe_value(1.5) == 1.5


class TestUntrustedText:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("GET", "GET"),
            ("/a\r\n/b", "/a/b"),
            ("/x\x1b[2Jy", "/x[2Jy"),
            ("\r\n\r\n", ""),
        ],
    )
    def test_crlf_and_control_characters_are_removed(self, raw: str, expected: str) -> None:
        assert untrusted_text(raw) == expected

    def test_truncates_like_safe_value(self) -> None:
        assert untrusted_text("y" * 50, max_chars=10) == safe_value("y" * 50, max_chars=10)

    def test_safe_value_delegates_for_strings(self) -> None:
        hostile = "a\nb\x00c" + "z" * 600
        assert safe_value(hostile) == untrusted_text(hostile)


class TestSecretScrubber:
    def test_literal_secret_is_redacted_from_message(self) -> None:
        payload = _format(_record(f"connecting with {SECRET}"), frozenset({SECRET}))
        assert SECRET not in json.dumps(payload)
        assert payload["message"] == f"connecting with {REDACTED}"

    def test_literal_secret_is_redacted_from_extra_fields(self) -> None:
        payload = _format(_record("x", detail=f"url=redis://:{SECRET}@redis"), frozenset({SECRET}))
        assert SECRET not in json.dumps(payload)
        assert REDACTED in str(payload["detail"])

    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "db_password",
            "secret",
            "api_key",
            "apiKey",
            "Authorization",
            "cookie",
            "token",
        ],
    )
    def test_sensitive_looking_keys_are_redacted_by_name(self, key: str) -> None:
        payload = _format(_record("x", **{key: "whatever"}))
        assert payload[key] == REDACTED

    def test_empty_secret_set_is_harmless(self) -> None:
        payload = _format(_record("hello"))
        assert payload["message"] == "hello"


class TestJsonFormatter:
    def test_untrusted_extra_cannot_forge_a_log_line(self) -> None:
        hostile = 'evil.example\n{"level": "INFO", "message": "forged"}\x1b[2J'
        payload = _format(_record("dns_query", query=hostile))
        assert "\n" not in str(payload["query"])
        assert "\x1b" not in str(payload["query"])
        assert payload["message"] == "dns_query"

    def test_format_args_are_cleaned_too(self) -> None:
        record = logging.LogRecord("t", logging.INFO, __file__, 1, "host=%s", ("a\r\nb",), None)
        payload = _format(record)
        assert payload["message"] == "host=ab"

    def test_correlation_id_is_attached_when_set(self) -> None:
        token = correlation_id_var.set("cid-123")
        try:
            payload = _format(_record("x"))
        finally:
            correlation_id_var.reset(token)
        assert payload["correlation_id"] == "cid-123"
        assert "correlation_id" not in _format(_record("x"))

    def test_exception_records_carry_type_only(self) -> None:
        try:
            raise RuntimeError(f"stack contains {SECRET} and /etc/passwd")
        except RuntimeError as exc:
            record = _record("boom")
            record.exc_info = (type(exc), exc, exc.__traceback__)
        line = JsonFormatter(SecretScrubber(frozenset({SECRET}))).format(record)
        payload = json.loads(line)
        assert payload["exception"] == "RuntimeError"
        assert "Traceback" not in line
        assert "/etc/passwd" not in line
        assert SECRET not in line
        assert __file__ not in line

    def test_standard_record_fields_are_not_duplicated(self) -> None:
        payload = _format(_record("x"))
        assert set(payload) == {"ts", "level", "logger", "message"}


def test_configure_logging_is_idempotent() -> None:
    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    try:
        configure_logging(level="WARNING")
        configure_logging(level="WARNING")
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
        assert root.level == logging.WARNING
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            assert logging.getLogger(name).handlers == []
            assert logging.getLogger(name).propagate is True
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in previous_handlers:
            root.addHandler(handler)
        root.setLevel(previous_level)
