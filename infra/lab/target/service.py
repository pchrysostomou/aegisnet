"""The lab's only service: an HTTP endpoint and a tiny DNS responder the generator talks to.

Everything here answers on the lab network and nowhere else. There is no outbound socket in
this file: the process binds, accepts and replies, which is what makes the lab's traffic
container-to-container by construction (docs/evaluation.md §7, E-1 and E-2).

Standard library only, so the lab runs on the project's own runtime image with no extra
dependency and no download.
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# `/private` is guarded by a marker header, not by a credential. The shape the lab needs is
# a burst of 401 responses; a username and password would add nothing to it except a
# credential-shaped literal in a repository whose secret scanning exists to keep those out.
OPERATOR_HEADER = "X-Aegisnet-Lab-Operator"

BODY = b"AegisNet lab target. Every byte here is generated inside an internal Docker network.\n"
BULK_CHUNK = b"aegisnet-lab-bulk-payload-" * 40  # 1 040 bytes of obviously synthetic filler


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisNetLabTarget/1"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"target: {self.address_string()} {fmt % args}", flush=True)  # noqa: T201

    def _send(self, code: int, body: bytes, *, extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send(200, b"ok\n")
        elif path == "/private":
            # With the marker header, allowed; without it, refused. The generator omits it on
            # purpose, so Suricata sees a run of refusals and records the shape D-002 reads.
            if self.headers.get(OPERATOR_HEADER):
                self._send(200, b"authorised\n")
            else:
                self._send(401, b"unauthorised\n", extra={"WWW-Authenticate": 'Basic realm="lab"'})
        elif path == "/bulk":
            size = _clamp(self.path)
            body = (BULK_CHUNK * (size // len(BULK_CHUNK) + 1))[:size]
            self._send(200, body)
        else:
            self._send(200, BODY)

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length", "0") or 0)
        read = 0
        while read < length:
            chunk = self.rfile.read(min(65536, length - read))
            if not chunk:
                break
            read += len(chunk)
        self._send(200, f"received {read}\n".encode())


def _clamp(path: str) -> int:
    _, _, query = path.partition("?")
    for item in query.split("&"):
        key, _, value = item.partition("=")
        if key == "bytes" and value.isdigit():
            return min(int(value), 8 * 1024 * 1024)
    return 64 * 1024


# ------------------------------------------------------------------ DNS

LAB_ZONE = "lab.example.test"
LAB_ANSWER = "203.0.113.10"


def _dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        labels.append(payload[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset


def _dns_reply(payload: bytes) -> bytes | None:
    """A minimal A-record responder: NOERROR inside the lab zone, NXDOMAIN outside it."""
    if len(payload) < 12:
        return None
    txid = payload[:2]
    name, end = _dns_name(payload, 12)
    if end + 4 > len(payload):
        return None
    question = payload[12 : end + 4]
    known = name.endswith(LAB_ZONE)
    flags = 0x8180 if known else 0x8183  # QR+RD+RA, NOERROR or NXDOMAIN
    header = txid + struct.pack(">HHHHH", flags, 1, 1 if known else 0, 0, 0)
    if not known:
        return header + question
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 1, 1, 60, 4)
        + bytes(int(part) for part in LAB_ANSWER.split("."))
    )
    return header + question + answer


def serve_dns(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))  # noqa: S104 - inside an internal-only lab network
    print(f"target: dns listening on {port}", flush=True)  # noqa: T201
    while True:
        payload, peer = sock.recvfrom(4096)
        reply = _dns_reply(payload)
        if reply is not None:
            sock.sendto(reply, peer)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--http-port", type=int, default=8080)
    # The beacon scenario checks in on its own port. Suricata (and D-004) group a
    # conversation by destination *and* port, so a beacon sharing 8080 with browsing,
    # uploads and auth failures disappears into their irregular timing — which is exactly
    # what the lab's first run demonstrated (docs/evaluation.md §9). A real beacon has its
    # own destination; giving it one here is fidelity, not threshold tuning.
    parser.add_argument("--beacon-port", type=int, default=9443)
    parser.add_argument("--dns-port", type=int, default=53)
    args = parser.parse_args()

    # Clear-text HTTP on purpose, and it has to be: the lab exists so that Suricata can
    # parse an application protocol and write EVE records about it. Under TLS there would be
    # no http records to read and nothing to test the detectors against. The traffic never
    # leaves an `internal: true` network with no default route, and every byte of it is
    # generated by the container next door. NOSONAR: S5332 is about exposing real traffic.
    threading.Thread(target=serve_dns, args=(args.dns_port,), daemon=True).start()
    beacon = ThreadingHTTPServer(("0.0.0.0", args.beacon_port), Handler)  # noqa: S104
    threading.Thread(target=beacon.serve_forever, daemon=True).start()  # NOSONAR
    print(f"target: beacon http listening on {args.beacon_port}", flush=True)  # noqa: T201
    server = ThreadingHTTPServer(("0.0.0.0", args.http_port), Handler)  # noqa: S104
    print(f"target: http listening on {args.http_port}", flush=True)  # noqa: T201
    server.serve_forever()  # NOSONAR
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
