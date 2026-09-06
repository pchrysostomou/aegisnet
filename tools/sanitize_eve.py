#!/usr/bin/env python3
"""Sanitise a Suricata EVE JSON capture so an excerpt can be committed (ADR-021).

This is the automated half of the lab pre-flight checklist's last step (docs/evaluation.md
§7, L-5: "eve.json is reviewed and sanitised before any excerpt is committed"). Its job is
not to make any capture publishable. Its job is to publish the narrow, boring case and to
**refuse everything else loudly**, because a capture that is interesting is a capture a
human needs to look at.

Three passes, in this order:

1. **Drop** records that describe the sensor rather than the network (``stats``, ``engine``),
   and records with no ``event_type`` at all.
2. **Strip** every field that can hold captured content, by key name, at any depth: payloads,
   packets, HTTP bodies and headers, file names and contents, certificate subjects,
   credentials, banners. The lab's own sensor writes none of these; the list exists because
   this tool is also the safety net for a capture taken with somebody else's configuration.
3. **Refuse** — write nothing at all, and say which line and which value stopped it — when
   what remains still contains:
   - a key that is neither stripped above nor on the published-key allowlist. A key nobody
     has classified is a key nobody has read, and this tool will not publish it;
   - an address outside RFC 1918, RFC 5737, loopback or link-local space, wherever it
     appears, including inside a longer string such as a URL;
   - a hostname outside the documentation domains, wherever it appears, including inside a
     certificate subject, a URL or a header value;
   - a line that is not one JSON object, or a structure nested past ``MAX_DEPTH``.

``--check`` re-runs the refusal pass against a file **exactly as it sits on disk**, with no
stripping, which is what makes it a meaningful assertion about a committed excerpt rather
than about a repaired copy of one.

Standard library only, so it runs with any Python 3.12 without the backend environment.

No path is accepted on the command line. Like a dataset import, this tool resolves fixed
names under the repository root it finds above its working directory: it reads the capture
`make lab-export` leaves at ``infra/lab/out/eve.json`` and writes
``samples/lab/lab-capture-01.ndjson`` beside its manifest. A sanitiser that took a path from
its caller would be a path its caller could point anywhere.

Usage:
    python3 tools/sanitize_eve.py --limit 500      # sanitise the last capture
    python3 tools/sanitize_eve.py --check          # re-verify the committed excerpt
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SANITIZER_VERSION = 2

# Records about the sensor, not about the network. They carry uptime, thread names, memory
# figures and the sensor's own identity, none of which belongs in a public repository and
# none of which the ingest path accepts anyway. Compared case-insensitively.
SENSOR_EVENT_TYPES = frozenset({"stats", "engine"})

# Keys that can carry captured bytes, credentials or somebody's identity, at any depth.
# Matched case-insensitively against the whole key, plus the prefixes below.
CONTENT_KEYS = frozenset(
    {
        "payload",
        "payload_printable",
        "packet",
        "packet_info",
        "http_request_body",
        "http_request_body_printable",
        "http_response_body",
        "http_response_body_printable",
        "request_body",
        "response_body",
        "request_headers",
        "response_headers",
        "file_data",
        "content",
        "certificate",
        "chain",
        "subject",
        "issuerdn",
        "serial",
        "fingerprint",
        "ja3",
        "ja3s",
        "ja4",
        "ja3_string",
        "ja3s_string",
        "email",
        "smtp",
        "smb",
        "krb5",
        "snmp",
        "ftp",
        "ftp_data",
        "ssh",
        "ike",
        "rdp",
        "mqtt",
        "sip",
        "filename",
        "magic",
        "md5",
        "sha1",
        "sha256",
        "host",
        "hostname_original",
        "capture_file",
        "pcap_filename",
        "user",
        "username",
        "password",
        "credentials",
        "command_data",
        "software_version",
        "banner",
        "cookie",
        "set_cookie",
        "authorization",
        "proxy_authorization",
        "referer",
        "http_refer",
        "redirect",
        "vars",
        "metadata",
    }
)
CONTENT_KEY_PREFIXES = ("payload", "packet", "body", "raw_", "pass", "secret", "token", "key_")

# What may be published. Every key in a record must be here or in CONTENT_KEYS; anything
# else stops the run by name. The list is what the lab's own sensor emits (alert, http,
# flow, dns, tcp) plus the record envelope — deliberately no wider, because a key nobody has
# classified is a key nobody has read.
PUBLISHED_KEYS = frozenset(
    {
        # envelope
        "timestamp",
        "event_type",
        "flow_id",
        "in_iface",
        "ip_v",
        "pkt_src",
        "direction",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "proto",
        "app_proto",
        "tx_id",
        "pcap_cnt",
        "community_id",
        "tenant_id",
        # alert
        "alert",
        "action",
        "gid",
        "signature_id",
        "rev",
        "signature",
        "category",
        "severity",
        # flow
        "flow",
        "pkts_toserver",
        "pkts_toclient",
        "bytes_toserver",
        "bytes_toclient",
        "start",
        "end",
        "age",
        "state",
        "reason",
        "alerted",
        "tx_cnt",
        "min_ttl",
        "max_ttl",
        # tcp / stream
        "tcp",
        "tcp_flags",
        "tcp_flags_ts",
        "tcp_flags_tc",
        "syn",
        "fin",
        "rst",
        "psh",
        "ack",
        "urg",
        "ecn",
        "cwr",
        "ttl",
        "ts_progress",
        "tc_progress",
        "ts_max_regions",
        "tc_max_regions",
        # Stream gap markers: Suricata says it missed bytes in one direction. Metadata about
        # the capture, carrying no content — classified here the first time a capture
        # produced one and the allowlist stopped the run, which is what it is for.
        "ts_gap",
        "tc_gap",
        # http
        "http",
        "http_port",
        "http_method",
        "http_user_agent",
        "http_content_type",
        "protocol",
        "status",
        "length",
        "url",
        "hostname",
        "http_response_status",
        # dns
        "dns",
        "type",
        "id",
        "version",
        "flags",
        "qr",
        "rd",
        "ra",
        "opcode",
        "rcode",
        "queries",
        "answers",
        "grouped",
        "rrname",
        "rrtype",
        "rdata",
        "ttl_dns",
        "aa",
        "tc",
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "PTR",
        "SOA",
        "SRV",
        "TXT",
        # anomaly
        "anomaly",
        "event",
        "layer",
        "code",
    }
)

# Addresses that may appear in committed data: RFC 1918, RFC 5737, loopback, link-local and
# the unspecified address. Anything else — including a real public address a misconfigured
# lab happened to see — stops the run.
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/32",
        "::1/128",
        "::/128",
        "fe80::/10",
        "fc00::/7",
    )
)

# Domains the evaluation plan allows in committed data (docs/evaluation.md §1, rule 4).
ALLOWED_DOMAINS = ("example.test", "example.com")

# Hostname-shaped tokens found anywhere inside a string: a URL's authority, a certificate
# subject's CN, a Host header. Matching a whole value is not enough — `CN=mail.acme.example`
# is not hostname-shaped, and the name inside it is exactly what must not be published.
HOSTNAME_TOKEN = re.compile(r"(?:[a-z0-9_-]{1,63}\.)+[a-z]{2,24}", re.IGNORECASE)
# Only tokens whose last label is a real top-level domain count, so `http.server`,
# `text/plain` and `suricata.yaml` are not mistaken for names.
CHECKED_TLDS = frozenset(
    [
        "com",
        "net",
        "org",
        "test",
        "example",
        "io",
        "dev",
        "local",
        "gov",
        "edu",
        "mil",
        "info",
        "biz",
        "co",
        "uk",
        "de",
        "fr",
        "nl",
        "eu",
        "ru",
        "cn",
        "jp",
        "us",
        "ca",
        "au",
        "ch",
        "se",
        "no",
        "es",
        "it",
        "pl",
        "br",
        "in",
        "xyz",
        "online",
        "site",
        "top",
        "cloud",
        "app",
        "ai",
        "me",
        "tv",
        "cc",
        "ly",
        "sh",
        "id",
    ]
)
ADDRESS_TOKEN = re.compile(
    r"[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}|\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE
)
# A URL or form value whose *parameter name* announces a secret. The value itself is
# unknowable, so the name is what this can act on: `?password=…` in a request line is a
# credential in the capture whatever it turns out to say.
SECRET_PARAMETER = re.compile(
    r"[?&;]\s*(pass|passwd|password|pwd|token|api[_-]?key|apikey|secret|auth|authorization"
    r"|session|sid|sig|signature|access[_-]?key|client[_-]?secret|code)\s*=",
    re.IGNORECASE,
)

MAX_STRING = 512
MAX_DEPTH = 24

# Where the tool reads and writes, relative to the repository root. Fixed, because nothing
# here should be steerable from a command line.
CAPTURE_FILE = Path("infra/lab/out/eve.json")
EXCERPT_FILE = Path("samples/lab/lab-capture-01.ndjson")
# What identifies a checkout: the lab that produces a capture and the registry that records
# the excerpt. Both are committed, so both exist before any capture is taken.
LAYOUT = (Path("infra/lab/docker-compose.lab.yml"), Path("samples/registry.yml"))


class UnpublishableCaptureError(ValueError):
    """The capture cannot be made safe by removing fields; a human has to look at it."""


def repository_root(start: Path) -> Path:
    """The nearest directory at or above ``start`` that holds the whole layout."""
    for candidate in (start, *start.parents):
        if all((candidate / relative).exists() for relative in LAYOUT):
            return candidate
    raise UnpublishableCaptureError(
        "not inside a repository checkout: "
        + ", ".join(str(relative) for relative in LAYOUT)
        + " were not all found at or above the working directory"
    )


# ---------------------------------------------------------------- key classification


def _is_content_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in CONTENT_KEYS or lowered.startswith(CONTENT_KEY_PREFIXES)


def _is_published_key(key: str) -> bool:
    return key in PUBLISHED_KEYS or key.lower() in PUBLISHED_KEYS


# ---------------------------------------------------------------- value checks


def _parse(token: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The token as an address, or ``None`` when it is a version, a date or a timestamp."""
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def _address_problem(text: str) -> str | None:
    """The first address in ``text`` that may not be published, wherever it sits."""
    for token in ADDRESS_TOKEN.findall(text):
        address = _parse(token)
        if address is None:
            continue
        if not any(address in network for network in ALLOWED_NETWORKS):
            return f"address {token!r} is outside documentation space"
    return None


def _name_problem(text: str) -> str | None:
    """The first hostname in ``text`` that is not a documentation name."""
    for token in HOSTNAME_TOKEN.findall(text):
        name = token.rstrip(".").lower()
        if name.rsplit(".", 1)[-1] not in CHECKED_TLDS:
            continue  # not a real top-level domain: a filename, a module path, a version
        if any(name == allowed or name.endswith(f".{allowed}") for allowed in ALLOWED_DOMAINS):
            continue
        return f"name {token!r} is outside example.test/example.com"
    return None


def _secret_problem(text: str) -> str | None:
    """A query or form parameter whose name says it carries a credential."""
    match = SECRET_PARAMETER.search(text)
    return None if match is None else f"parameter {match.group(1)!r} carries a credential"


def check_scalar(value: Any) -> list[str]:
    """Everything wrong with one leaf value. Non-strings carry nothing to check."""
    if not isinstance(value, str):
        return []
    checks = (_address_problem(value), _name_problem(value), _secret_problem(value))
    return [problem for problem in checks if problem]


def audit(node: Any, *, path: str = "", depth: int = 0, strict_keys: bool = True) -> list[str]:
    """Every reason this record may not be published.

    Reaches every scalar, whether it arrived as a dict value, a list element, or a list
    element inside a list — the case that matters, because Suricata puts addresses in lists
    (``dns.answers``, ``dns.grouped.A``).
    """
    if depth > MAX_DEPTH:
        return [f"{path or '<record>'}: nested deeper than {MAX_DEPTH} levels"]
    problems: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if strict_keys and not _is_published_key(str(key)) and not _is_content_key(str(key)):
                problems.append(f"{here}: key {key!r} is not on the published-key list")
                continue
            if strict_keys and _is_content_key(str(key)):
                problems.append(f"{here}: key {key!r} can carry captured content")
                continue
            problems.extend(audit(value, path=here, depth=depth + 1, strict_keys=strict_keys))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            problems.extend(
                audit(item, path=f"{path}[{index}]", depth=depth + 1, strict_keys=strict_keys)
            )
    else:
        problems.extend(f"{path or '<value>'}: {problem}" for problem in check_scalar(node))
    return problems


# ---------------------------------------------------------------- stripping


def strip_content(value: Any, *, depth: int = 0) -> Any:
    """Drop every content-bearing key at any depth and bound every remaining string."""
    if depth > MAX_DEPTH:
        raise UnpublishableCaptureError(f"record nests deeper than {MAX_DEPTH} levels")
    if isinstance(value, dict):
        return {
            key: strip_content(item, depth=depth + 1)
            for key, item in value.items()
            if not _is_content_key(str(key))
        }
    if isinstance(value, list):
        return [strip_content(item, depth=depth + 1) for item in value]
    if isinstance(value, str) and len(value) > MAX_STRING:
        return value[:MAX_STRING]
    return value


# ---------------------------------------------------------------- the passes


def sanitize_line(line: str) -> dict[str, Any] | None:
    """One EVE line as a publishable record, or ``None`` when it describes the sensor."""
    record = json.loads(line)
    if not isinstance(record, dict):
        raise UnpublishableCaptureError("every line must be a JSON object")
    kind = record.get("event_type")
    if not isinstance(kind, str) or not kind.strip():
        raise UnpublishableCaptureError("a record without an event_type is not EVE output")
    if kind.strip().lower() in SENSOR_EVENT_TYPES:
        return None
    return strip_content(record)


def sanitize(lines: list[str], *, limit: int | None = None) -> tuple[list[dict[str, Any]], Counter]:
    """Strip, then refuse. Returns the publishable records and what was dropped."""
    kept: list[dict[str, Any]] = []
    dropped: Counter = Counter()
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = sanitize_line(line)
        except json.JSONDecodeError as error:
            raise UnpublishableCaptureError(f"line {number} is not JSON: {error}") from error
        if record is None:
            dropped["sensor_record"] += 1
            continue
        problems = audit(record)
        if problems:
            raise UnpublishableCaptureError(f"line {number}: " + "; ".join(problems[:3]))
        kept.append(record)
        if limit is not None and len(kept) >= limit:
            dropped["over_limit"] = max(0, len(lines) - number)
            break
    return kept, dropped


def verify(lines: list[str]) -> int:
    """Check a file exactly as it sits on disk: nothing is stripped first, so a payload or a
    sensor record present in the bytes is a failure rather than something quietly removed.
    Returns the record count."""
    count = 0
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise UnpublishableCaptureError(f"line {number} is not JSON: {error}") from error
        if not isinstance(record, dict):
            raise UnpublishableCaptureError(f"line {number} is not a JSON object")
        kind = str(record.get("event_type", "")).strip().lower()
        if not kind:
            raise UnpublishableCaptureError(f"line {number} has no event_type")
        if kind in SENSOR_EVENT_TYPES:
            raise UnpublishableCaptureError(f"line {number} is a {kind} record about the sensor")
        problems = audit(record)
        if problems:
            raise UnpublishableCaptureError(f"line {number}: " + "; ".join(problems[:3]))
        count += 1
    if count == 0:
        raise UnpublishableCaptureError("no records")
    return count


# ---------------------------------------------------------------- output


def _hour_window(first: str, last: str) -> dict[str, str]:
    """The hour-aligned interval a detection sweep should cover for this capture, so the
    operator (and `make eval-lab`) never has to work it out from timestamps by hand."""
    try:
        start = datetime.fromisoformat(first.replace("Z", "+00:00"))
        end = datetime.fromisoformat(last.replace("Z", "+00:00"))
    except ValueError:
        return {}
    floor = start.replace(minute=0, second=0, microsecond=0)
    ceiling = end.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    return {
        "from": floor.isoformat().replace("+00:00", "Z"),
        "to": ceiling.isoformat().replace("+00:00", "Z"),
    }


def manifest_for(
    records: list[dict[str, Any]], dropped: Counter, source: Path, payload: bytes
) -> dict[str, Any]:
    first = min((str(r.get("timestamp", "")) for r in records), default="")
    last = max((str(r.get("timestamp", "")) for r in records), default="")
    return {
        "sanitizer": "tools/sanitize_eve.py",
        "sanitizer_version": SANITIZER_VERSION,
        "source_name": source.name,
        "events": len(records),
        "counts_by_type": dict(sorted(Counter(str(r.get("event_type")) for r in records).items())),
        "dropped": dict(sorted(dropped.items())),
        "time_range": {"start": first, "end": last},
        "sweep_window": _hour_window(first, last),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
        "addressing": "RFC 5737 documentation range only; every address verified by the sanitiser",
        "content": (
            "Real Suricata output captured in the isolated lab (infra/lab/, ADR-021). "
            "Sensor records, payloads, packets and bodies removed; nothing here was captured "
            "from a real network."
        ),
    }


def manifest_path_for(out: Path) -> Path:
    """``lab-capture-01.ndjson`` → ``lab-capture-01.manifest.json``, without eating a date or
    a version out of the middle of the name."""
    return out.with_name(f"{out.stem}.manifest.json")


def _lines(path: Path) -> Iterator[str]:
    """Read a capture a line at a time; an eve.json can be very large."""
    with path.open(encoding="utf-8") as handle:
        yield from (line.rstrip("\n") for line in handle)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--limit", type=int, default=None, help="keep at most this many records")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed excerpt as it sits on disk instead of writing one",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        root = repository_root(Path.cwd())
    except UnpublishableCaptureError as error:
        print(f"error: {error}", file=sys.stderr)  # noqa: T201 - CLI output
        return 1

    excerpt = root / EXCERPT_FILE
    if args.check:
        try:
            count = verify(list(_lines(excerpt)))
        except (UnpublishableCaptureError, OSError, UnicodeDecodeError) as error:
            print(f"error: {EXCERPT_FILE}: {error}", file=sys.stderr)  # noqa: T201 - CLI output
            return 1
        print(f"{EXCERPT_FILE}: {count} records, publishable")  # noqa: T201 - CLI output
        return 0

    source = root / CAPTURE_FILE
    try:
        records, dropped = sanitize(list(_lines(source)), limit=args.limit)
    except (UnpublishableCaptureError, OSError, UnicodeDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)  # noqa: T201 - CLI output
        return 1
    if not records:
        print("error: nothing left to publish", file=sys.stderr)  # noqa: T201 - CLI output
        return 1
    payload = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records).encode()
    excerpt.parent.mkdir(parents=True, exist_ok=True)
    excerpt.write_bytes(payload)
    manifest_path = manifest_path_for(excerpt)
    manifest_path.write_text(
        json.dumps(manifest_for(records, dropped, source, payload), indent=2) + "\n",
        encoding="utf-8",
    )
    counts = Counter(str(record.get("event_type")) for record in records)
    kinds = ", ".join(f"{kind} {count}" for kind, count in sorted(counts.items()))
    print(f"{EXCERPT_FILE}: {len(records)} records ({kinds})")  # noqa: T201 - CLI output
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
