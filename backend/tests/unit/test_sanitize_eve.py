"""tools/sanitize_eve.py: what it strips, what it drops, and what it refuses (ADR-021).

The sanitiser is the automated half of the lab checklist's last step, so its tests are
written from the other side: each one feeds it something that must never be published and
asserts that the tool either removes it or refuses to write the file at all.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

TOOL = REPO_ROOT / "tools" / "sanitize_eve.py"
EXCERPT = REPO_ROOT / "samples" / "lab" / "lab-capture-01.ndjson"
MANIFEST = REPO_ROOT / "samples" / "lab" / "lab-capture-01.manifest.json"


def _module() -> Any:
    """Load the tool the way the other tools/ tests do: by path, without installing it."""
    spec = importlib.util.spec_from_file_location("sanitize_eve", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sanitize_eve = _module()


def _line(**overrides: Any) -> str:
    record: dict[str, Any] = {
        "timestamp": "2026-09-05T18:00:00.000000+0000",
        "event_type": "flow",
        "src_ip": "203.0.113.20",
        "dest_ip": "203.0.113.10",
        "src_port": 40000,
        "dest_port": 8080,
        "proto": "TCP",
        "flow": {"bytes_toserver": 100, "bytes_toclient": 200},
    }
    record.update(overrides)
    return json.dumps(record)


def _published(line: str) -> dict[str, Any]:
    [record], _ = sanitize_eve.sanitize([line])
    return record


def test_sensor_records_are_dropped_not_published() -> None:
    kept, dropped = sanitize_eve.sanitize([_line(), _line(event_type="stats", stats={"uptime": 9})])
    assert [r["event_type"] for r in kept] == ["flow"]
    assert dropped["sensor_record"] == 1


def test_every_content_bearing_field_is_removed_at_any_depth() -> None:
    record = _published(
        _line(
            payload="dGhlIGJ5dGVz",
            packet="AAAA",
            http={
                "hostname": "host.example.test",
                "http_response_body": "secret",
                "url": "/x",
                "cookie": "session=abc",
            },
        )
    )
    text = json.dumps(record)
    for gone in ("payload", "packet", "http_response_body", "cookie", "session=abc"):
        assert gone not in text, gone
    assert record["http"]["hostname"] == "host.example.test", "ordinary fields survive"
    assert record["http"]["url"] == "/x"


def test_long_strings_are_bounded() -> None:
    record = _published(_line(http={"url": "/" + "a" * 5000}))
    assert len(record["http"]["url"]) == sanitize_eve.MAX_STRING


@pytest.mark.parametrize(
    "line",
    [
        _line(dest_ip="8.8.8.8"),
        _line(src_ip="93.184.216.34"),
        _line(dns={"rrname": "www.realdomain.org", "rdata": "1.2.3.4"}),
    ],
    ids=["public-dest", "public-src", "real-name-and-address"],
)
def test_a_capture_that_still_names_the_real_internet_is_refused(line: str) -> None:
    """Refusal, not redaction: a capture that saw the internet needs a human, not a filter."""
    with pytest.raises(sanitize_eve.UnpublishableCaptureError):
        sanitize_eve.sanitize([line])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ({"http": {"url": "http://intranet.acme.com/secret"}}, "a real host inside a URL"),
        ({"http": {"hostname": "portal.example.org"}}, "a real host in a Host header"),
        ({"dns": {"rrname": "telemetry.vendor.net"}}, "a real name in a DNS record"),
        ({"alert": {"signature": "ET MALWARE seen at cdn.badthing.net"}}, "a name in a signature"),
    ],
    ids=["url", "host-header", "dns", "signature"],
)
def test_a_real_name_hidden_inside_a_value_is_refused(field: dict[str, Any], value: str) -> None:
    """A hostname is just as published sitting in a URL as in a hostname field, so names are
    looked for inside every string, not only in the fields that are supposed to hold them."""
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match=r"outside example\.test"):
        sanitize_eve.sanitize([_line(**field)])


@pytest.mark.parametrize(
    ("field", "secret"),
    [
        ({"http": {"request_headers": [{"name": "Cookie", "value": "s=abc"}], "url": "/a"}}, "abc"),
        ({"http": {"cookie": "session=abc", "url": "/a"}}, "session"),
        ({"http": {"http_refer": "https://portal.example.com/x", "url": "/a"}}, "portal"),
        ({"ssh": {"client": {"software_version": "OpenSSH_9.6"}}}, "OpenSSH"),
    ],
    ids=["request-headers", "cookie", "referer", "ssh-banner"],
)
def test_fields_a_foreign_sensor_configuration_can_add_are_stripped(
    field: dict[str, Any], secret: str
) -> None:
    """The lab's sensor writes none of these. A capture taken elsewhere can, and each one
    carries a name, a credential or a file, so they go before anything else is decided."""
    assert secret not in json.dumps(_published(_line(**field)))


@pytest.mark.parametrize(
    "record",
    [
        {"tls": {"subject": "CN=mail.acme.com, O=Acme"}},
        {"fileinfo": {"filename": "/home/someone/quarterly-results.xlsx"}},
        {"anomaly_v2": {"event": "x"}},
    ],
    ids=["tls", "fileinfo", "unknown-block"],
)
def test_a_whole_record_type_the_lab_never_produces_is_refused(record: dict[str, Any]) -> None:
    """These blocks are stripped wholesale by key, which leaves a record whose own top-level
    key is unclassified — and an unclassified key stops the run rather than being guessed at."""
    with pytest.raises(sanitize_eve.UnpublishableCaptureError):
        sanitize_eve.sanitize([_line(**record)])


def test_a_name_that_is_not_a_hostname_survives() -> None:
    """The check would be noise if it flagged every dotted string, so only real top-level
    domains count: a content type, a version and a module path are left alone."""
    record = _published(
        _line(http={"http_content_type": "text/plain", "protocol": "HTTP/1.1", "url": "/a.b.c"})
    )
    assert record["http"]["http_content_type"] == "text/plain"
    assert record["http"]["url"] == "/a.b.c"


def test_documentation_and_private_space_are_accepted() -> None:
    lines = [
        _line(dest_ip="198.51.100.7"),
        _line(dest_ip="10.10.0.5"),
        _line(dest_ip="127.0.0.1"),
        _line(dns={"rrname": "host.lab.example.test", "rrtype": "A"}),
    ]
    kept, _ = sanitize_eve.sanitize(lines)
    assert len(kept) == 4


@pytest.mark.parametrize(
    "record",
    [
        {"dns": {"grouped": {"A": ["93.184.216.34"]}}},
        {"dns": {"answers": [{"rrname": "a.example.test", "rdata": "93.184.216.34"}]}},
        {"dns": {"answers": [{"rrname": "telemetry.vendor.net", "rrtype": "A"}]}},
    ],
    ids=["address-in-a-list", "address-in-a-list-of-objects", "name-in-a-list-of-objects"],
)
def test_a_value_hidden_in_a_list_is_reached(record: dict[str, Any]) -> None:
    """Suricata puts addresses in lists. A checker that only walks dictionaries reads none of
    them, which is the shape of bug that publishes a real address."""
    with pytest.raises(sanitize_eve.UnpublishableCaptureError):
        sanitize_eve.sanitize([_line(**record)])


def test_a_key_nobody_classified_stops_the_run_by_name() -> None:
    """The allowlist is the point: an unrecognised key has not been read by anyone, so it is
    refused rather than published or silently dropped."""
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match="operator_note"):
        sanitize_eve.sanitize([_line(operator_note="internal")])
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match="quic"):
        sanitize_eve.sanitize([_line(quic={"version": 1})])


# Built from expressions rather than written out: the secret-scanning job rejects a
# secret-shaped literal even in a test that exists to prove secrets are refused.
NOT_A_SECRET = "x" * 12


@pytest.mark.parametrize(
    "parameter",
    ["password", "api_key", "token", "client_secret", "code"],
)
def test_a_url_whose_parameter_announces_a_credential_is_refused(parameter: str) -> None:
    """The value is unknowable; the parameter name is not, and it is enough to stop."""
    url = f"/login?user=operator&{parameter}={NOT_A_SECRET}"
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match="credential"):
        sanitize_eve.sanitize([_line(event_type="http", http={"url": url})])


def test_a_record_without_an_event_type_is_refused() -> None:
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match="event_type"):
        sanitize_eve.sanitize(['{"timestamp": "2026-09-05T18:00:00.000000+0000"}'])


def test_sensor_records_are_recognised_whatever_their_case() -> None:
    _, dropped = sanitize_eve.sanitize([_line(), _line(event_type="Stats")])
    assert dropped["sensor_record"] == 1


def test_check_judges_the_file_on_disk_not_a_repaired_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that still holds packet bytes is not publishable, however easily the tool could
    have removed them; --check is an assertion about the committed bytes."""
    root = _checkout(tmp_path, "")
    monkeypatch.chdir(root)
    excerpt = root / sanitize_eve.EXCERPT_FILE
    excerpt.parent.mkdir(parents=True, exist_ok=True)
    excerpt.write_text(_line(payload="R0VU") + "\n", encoding="utf-8")
    assert sanitize_eve.main(["--check"]) == 1
    excerpt.write_text(_line(event_type="stats") + "\n", encoding="utf-8")
    assert sanitize_eve.main(["--check"]) == 1
    excerpt.write_text(_line() + "\n", encoding="utf-8")
    assert sanitize_eve.main(["--check"]) == 0


def test_the_manifest_name_keeps_the_whole_stem() -> None:
    """`lab-capture-2026-09-06.ndjson` must not lose its date to suffix stripping."""
    assert sanitize_eve.manifest_path_for(Path("a/lab-capture-2026-09-06.ndjson")).name == (
        "lab-capture-2026-09-06.manifest.json"
    )


def test_a_structure_nested_past_the_bound_is_refused() -> None:
    deep: Any = "x"
    for _ in range(sanitize_eve.MAX_DEPTH + 2):
        deep = [deep]
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match="deeper"):
        sanitize_eve.sanitize([_line(dns=deep)])


def test_malformed_input_is_refused_with_the_line_number() -> None:
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match="line 2"):
        sanitize_eve.sanitize([_line(), "{not json"])
    with pytest.raises(sanitize_eve.UnpublishableCaptureError, match="JSON object"):
        sanitize_eve.sanitize(["[1, 2, 3]"])


def test_the_limit_stops_early_and_is_recorded() -> None:
    kept, dropped = sanitize_eve.sanitize([_line() for _ in range(10)], limit=3)
    assert len(kept) == 3 and dropped["over_limit"] == 7


def test_the_manifest_publishes_the_hour_aligned_sweep_window() -> None:
    records = [
        json.loads(_line(timestamp="2026-09-05T18:41:00.000000+0000")),
        json.loads(_line(timestamp="2026-09-05T19:05:00.000000+0000")),
    ]
    manifest = sanitize_eve.manifest_for(records, sanitize_eve.Counter(), Path("eve.json"), b"x")
    assert manifest["sweep_window"] == {
        "from": "2026-09-05T18:00:00Z",
        "to": "2026-09-05T20:00:00Z",
    }
    assert manifest["counts_by_type"] == {"flow": 2}
    assert manifest["sanitizer_version"] == sanitize_eve.SANITIZER_VERSION


def _checkout(tmp_path: Path, capture: str) -> Path:
    """A miniature checkout: the two files the tool uses to recognise one, plus a capture."""
    for marker in sanitize_eve.LAYOUT:
        (tmp_path / marker).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / marker).write_text("marker\n", encoding="utf-8")
    source = tmp_path / sanitize_eve.CAPTURE_FILE
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(capture, encoding="utf-8")
    return tmp_path


def test_the_cli_takes_no_paths_and_writes_beside_the_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fixed names under a discovered root: a sanitiser that took a path from its caller
    would be a path its caller could point anywhere."""
    root = _checkout(tmp_path, "\n".join([_line(), _line(event_type="stats")]) + "\n")
    monkeypatch.chdir(root / "infra" / "lab")
    assert sanitize_eve.main([]) == 0
    excerpt = root / sanitize_eve.EXCERPT_FILE
    assert len(excerpt.read_text(encoding="utf-8").splitlines()) == 1
    manifest = json.loads(sanitize_eve.manifest_path_for(excerpt).read_text(encoding="utf-8"))
    assert manifest["events"] == 1 and manifest["dropped"] == {"sensor_record": 1}
    assert sanitize_eve.main(["--check"]) == 0


def test_the_cli_refuses_to_run_outside_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert sanitize_eve.main([]) == 1
    assert "not inside a repository checkout" in capsys.readouterr().err


def test_the_cli_refuses_an_unpublishable_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _checkout(tmp_path, _line(dest_ip="8.8.8.8") + "\n")
    monkeypatch.chdir(root)
    assert sanitize_eve.main([]) == 1
    assert not (root / sanitize_eve.EXCERPT_FILE).exists(), "nothing is written on a refusal"


@pytest.mark.skipif(not EXCERPT.is_file(), reason="the committed lab excerpt is absent")
def test_the_committed_lab_excerpt_is_still_publishable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The excerpt in samples/lab/ must survive its own sanitiser, forever."""
    monkeypatch.chdir(REPO_ROOT)
    assert sanitize_eve.main(["--check"]) == 0
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    lines = [line for line in EXCERPT.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert manifest["events"] == len(lines)
    assert set(manifest["counts_by_type"]) <= {
        "alert",
        "dns",
        "flow",
        "http",
        "tls",
        "anomaly",
        "fileinfo",
    }
