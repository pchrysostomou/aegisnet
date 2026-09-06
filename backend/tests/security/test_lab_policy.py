"""The isolated Suricata lab declares what docs/evaluation.md §7 requires of it (ADR-021).

Like the rest of this module these tests read the committed files as data. They prove what
the lab *declares*, not what a running lab does: L-0's real proof is the pre-flight command
`make lab-preflight`, which asks the running container whether it has a default route. What
a file can be held to is held to here, and the checklist step each test serves is named in
its docstring.

The one hardening exception in the repository lives in this file's assertions: the sensor
adds CAP_NET_RAW back after dropping everything, because no capability-less process can open
a packet socket. The test pins the exception to that single service and that single
capability, so widening it is a decision somebody has to make in the open.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.security

LAB_DIR = REPO_ROOT / "infra" / "lab"
LAB_COMPOSE = LAB_DIR / "docker-compose.lab.yml"
LAB_RULES = LAB_DIR / "suricata" / "lab.rules"
LAB_SURICATA = LAB_DIR / "suricata" / "suricata.yaml"
LAB_SCRIPTS = (LAB_DIR / "generators" / "traffic.py", LAB_DIR / "target" / "service.py")
LAB_SUBNET = ipaddress.ip_network("203.0.113.0/24")

# Every address that may appear anywhere under infra/lab/: the lab's own documentation
# range, RFC 1918, loopback and the bind-any address (docs/evaluation.md §1, rule 4).
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "203.0.113.0/24",
        "198.51.100.0/24",
        "192.0.2.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "0.0.0.0/32",
    )
)
ADDRESS_LITERAL = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
HOSTNAME_LITERAL = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
ALLOWED_DOMAINS = (".example.test", ".example.com", "example.test", "example.com")
# Only literals ending in one of these are treated as hostnames at all. Source code is full
# of dotted names that are not addresses — `http.server`, `docker-compose.lab.yml`,
# `aegisnet.domain.detectors` — and flagging them would make the check noise.
CHECKED_TLDS = ("test", "com", "net", "org", "io", "dev", "local")

# Configuration and command-line markers that would mean Suricata is inline rather than
# watching (docs/evaluation.md §7 L-4). Suricata cannot drop a packet it never routes, so
# the absence of every one of these is what "IDS only" means as a property of the files.
INLINE_MARKERS = (
    "nfq",
    "nfqueue",
    "ipfw",
    "netmap",
    "copy-mode",
    "copy-iface",
    "ips-mode",
    "inline",
    "--simulate-ips",
)
IPS_RULE_ACTIONS = ("drop", "reject", "rejectsrc", "rejectdst", "rejectboth")

# Tooling a lab like this must never contain. docs/PRD.md makes scanning, exploitation and
# brute-forcing permanent non-goals, so the lab may not reach for anyone's implementation
# of them either.
FORBIDDEN_TOOLING = (
    "nmap",
    "masscan",
    "zmap",
    "hydra",
    "metasploit",
    "msfconsole",
    "sqlmap",
    "nikto",
    "hping",
    "scapy",
    "tcpreplay",
    "ettercap",
    "aircrack",
)


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _services() -> dict[str, dict[str, Any]]:
    services = _load(LAB_COMPOSE)["services"]
    assert isinstance(services, dict)
    return services


def _address(literal: str) -> bool:
    try:
        ipaddress.ip_address(literal)
    except ValueError:
        return False
    return True


def _lab_files() -> list[Path]:
    """Every committed file of the lab. `out/` is excluded: it holds whatever the operator's
    last run produced, it is ignored by git, and it is not part of what ships."""
    return sorted(
        path
        for path in LAB_DIR.rglob("*")
        if path.is_file()
        and path.name != ".gitignore"
        and "out" not in path.relative_to(LAB_DIR).parts
    )


def test_the_lab_lives_where_every_document_says_it_does() -> None:
    """ARCHITECTURE.md, docs/delivery-plan.md and docs/repo-structure.md all name this path."""
    assert LAB_COMPOSE.is_file()
    assert LAB_RULES.is_file() and LAB_SURICATA.is_file()
    for script in LAB_SCRIPTS:
        assert script.is_file(), script


def test_every_lab_service_is_opt_in_behind_the_lab_profile() -> None:
    """Nothing starts by accident: `docker compose -f …lab.yml up` with no profile is a no-op."""
    services = _services()
    assert set(services) == {"target", "suricata", "generator"}
    for name, service in services.items():
        assert service.get("profiles") == ["lab"], name


def test_the_lab_network_is_internal_and_uses_documentation_space() -> None:
    """L-0: `internal: true` is what leaves the bridge with no route off the host."""
    network = _load(LAB_COMPOSE)["networks"]["lab"]
    assert network["name"] == "aegisnet_lab", (
        "the name docs/evaluation.md §7 L-0 tells the operator to inspect"
    )
    assert network["internal"] is True
    subnets = [ipaddress.ip_network(entry["subnet"]) for entry in network["ipam"]["config"]]
    assert subnets == [LAB_SUBNET]


def test_no_lab_service_publishes_a_port_or_shares_a_host_namespace() -> None:
    """T-5.2 and the safety rule that no traffic reaches anything outside the lab."""
    for name, service in _services().items():
        assert "ports" not in service, name
        assert "expose" not in service, name
        for key in ("pid", "ipc", "uts"):
            assert service.get(key) != "host", f"{name} shares the host {key}"
        assert service.get("network_mode") != "host", name
        for volume in service.get("volumes", []):
            assert "docker.sock" not in str(volume), name


def test_the_sensor_shares_the_target_container_namespace_only() -> None:
    """How one process watches a conversation between two containers without a host interface."""
    assert _services()["suricata"]["network_mode"] == "service:target"


def test_capabilities_are_dropped_everywhere_and_added_back_only_for_capture() -> None:
    """The repository's single hardening exception, pinned to one service and one capability."""
    for name, service in _services().items():
        assert service.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in service.get("security_opt", []), name
        assert not service.get("privileged"), name
    added = {name: service.get("cap_add", []) for name, service in _services().items()}
    assert added == {"target": [], "suricata": ["NET_RAW"], "generator": []}


def test_the_sensor_image_is_pinned_by_digest() -> None:
    """A lab whose sensor changed under the operator would invalidate every number it produced."""
    image = _services()["suricata"]["image"]
    assert re.match(r"^jasonish/suricata:\d+\.\d+@sha256:[0-9a-f]{64}$", image), image


def test_the_lab_holds_no_credential_and_reaches_no_datastore() -> None:
    """The lab produces a file; it never touches PostgreSQL, Redis, the spool or a secret."""
    for name, service in _services().items():
        assert "env_file" not in service, name
        environment = service.get("environment", {})
        keys = (
            environment
            if isinstance(environment, dict)
            else dict(item.split("=", 1) for item in environment)
        )
        for key in keys:
            assert not re.search(r"(PASSWORD|SECRET|TOKEN|API[_-]?KEY)", str(key), re.IGNORECASE), (
                f"{name} sets {key}"
            )
            assert not str(key).startswith(("POSTGRES_", "REDIS_", "SPOOL_")), f"{name} sets {key}"


@pytest.mark.parametrize("marker", INLINE_MARKERS)
def test_the_sensor_configuration_declares_no_inline_mode(marker: str) -> None:
    """L-4: IDS only. None of Suricata's inline transports or modes appears anywhere."""
    text = LAB_SURICATA.read_text(encoding="utf-8").lower()
    command = " ".join(str(token) for token in _services()["suricata"].get("command", [])).lower()
    # `inline` appears in this file's own prose about not being inline; only settings count.
    settings = "\n".join(
        line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")
    )
    assert marker not in settings, f"{marker} in suricata.yaml"
    assert marker not in command, f"{marker} on the sensor command line"


def test_every_lab_rule_only_alerts() -> None:
    """L-4 again, from the other side: no rule can drop, reject or otherwise act on traffic."""
    rules = [
        line.strip()
        for line in LAB_RULES.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert rules, "the lab ships at least one rule"
    for rule in rules:
        action = rule.split(" ", 1)[0]
        assert action == "alert", f"rule action {action!r} is not alert: {rule[:70]}"
        for forbidden in IPS_RULE_ACTIONS:
            assert not rule.startswith(forbidden), rule[:70]


def test_lab_rules_are_local_and_never_downloaded() -> None:
    """The lab network has no route out; a rule fetch would be both broken and unreviewed.

    Prose may name `suricata-update` — the compose file and the runbook both explain that it
    never runs — so what is asserted is that nothing *invokes* it and that no rule source is
    a URL."""
    assert "lab.rules" in LAB_SURICATA.read_text(encoding="utf-8")
    sensor = _services()["suricata"]
    invocation = " ".join(
        str(token) for key in ("command", "entrypoint") for token in sensor.get(key, [])
    )
    assert "suricata-update" not in invocation
    assert "ENABLE_CRON" not in str(sensor.get("environment", {}))
    for path in _lab_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "http://" not in text.replace("http://127.0.0.1", "").replace(
            "config reference: url http://", ""
        ), f"{path.name} carries an http:// URL"


@pytest.mark.parametrize("path", _lab_files(), ids=lambda p: str(p.relative_to(LAB_DIR)))
def test_no_lab_file_names_an_address_outside_documentation_space(path: Path) -> None:
    """L-2: the generator (and everything beside it) can only ever talk inside the lab."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for literal in ADDRESS_LITERAL.findall(text):
        # A four-number literal that is not an address at all (a version, a date) is not this
        # test's business; only real addresses are checked.
        if not _address(literal):
            continue
        address = ipaddress.ip_address(literal)
        assert any(address in network for network in ALLOWED_NETWORKS), (
            f"{path.name} names {literal}, which is outside documentation and private space"
        )


@pytest.mark.parametrize("path", _lab_files(), ids=lambda p: str(p.relative_to(LAB_DIR)))
def test_no_lab_file_names_a_domain_outside_the_documentation_domains(path: Path) -> None:
    """docs/evaluation.md §1 rule 4: example.test and example.com, and nothing else."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for literal in HOSTNAME_LITERAL.findall(text):
        lowered = literal.lower().rstrip(".")
        if not lowered.endswith(tuple(f".{tld}" for tld in CHECKED_TLDS)):
            continue
        assert lowered.endswith(ALLOWED_DOMAINS), (
            f"{path.name} names {literal!r}, which is not a documentation domain"
        )


@pytest.mark.parametrize("tool", FORBIDDEN_TOOLING)
def test_the_lab_contains_no_offensive_tooling(tool: str) -> None:
    """docs/PRD.md's permanent non-goals: no scanner, no exploitation, no brute-force tool."""
    for path in _lab_files():
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        assert tool not in text, f"{path.name} mentions {tool}"


def test_the_generator_targets_the_lab_and_nothing_else() -> None:
    """L-2's real subject: every destination the generator opens is the lab's own target."""
    source = (LAB_DIR / "generators" / "traffic.py").read_text(encoding="utf-8")
    assert 'TARGET_HOST = "target"' in source
    # Every socket call goes through TARGET_HOST; no other destination is ever constructed.
    for call in ("connect((", "sendto(", "HTTPConnection("):
        for line in source.splitlines():
            if call in line:
                assert "TARGET_HOST" in line, f"{call} without TARGET_HOST: {line.strip()}"


def test_the_raw_capture_can_never_be_committed() -> None:
    """L-5: raw sensor output stays on the operator's machine; only a sanitised excerpt ships.

    The directory is not asserted to be *empty* — after `make lab-capture` it holds the run
    the operator just took. It is asserted to be unable to reach git."""
    out = LAB_DIR / "out"
    ignore = [
        line.strip() for line in (out / ".gitignore").read_text(encoding="utf-8").splitlines()
    ]
    assert ignore[0] == "*" and "!.gitignore" in ignore
    root_ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("eve*.json", "*.pcap", "*.pcapng"):
        assert pattern in root_ignore, pattern


def test_the_sensor_writes_into_a_volume_the_teardown_removes() -> None:
    """A capture lives in a named volume until `make lab-export` copies it out, and
    `make lab-clean` (`down --volumes`) takes it away again."""
    manifest = _load(LAB_COMPOSE)
    assert "lab_capture" in manifest["volumes"]
    sensor = _services()["suricata"]
    assert "lab_capture:/capture" in sensor["volumes"]
    # The mount point is deliberately not the image's own log directory; the sensor runs as
    # root with no CAP_DAC_OVERRIDE and could not write into a directory the image owns.
    assert not any("/var/log/suricata" in str(v) for v in sensor["volumes"])
    assert "lab_capture:/capture:ro" in _services()["generator"]["volumes"]


def test_every_lab_rule_uses_the_reserved_signature_id_range() -> None:
    """9100000-9199999 belongs to the lab, so a lab alert can never be mistaken for another
    ruleset's, nor for the synthetic corpus's 9000001-9000002."""
    sids = [int(sid) for sid in re.findall(r"sid:(\d+);", LAB_RULES.read_text(encoding="utf-8"))]
    assert sids, "every rule carries a sid"
    for sid in sids:
        assert 9_100_000 <= sid <= 9_199_999, sid
    assert len(set(sids)) == len(sids), "sids are unique"


def test_a_lab_rule_message_matches_a_detector_pattern() -> None:
    """The lab is only useful if what it produces can reach a rule: D-002 reads signature text."""
    from aegisnet.domain.detectors.auth_burst import DEFAULT_PATTERNS

    messages = re.findall(r'msg:"([^"]+)"', LAB_RULES.read_text(encoding="utf-8"))
    assert messages
    assert any(
        pattern in message.lower() for message in messages for pattern in DEFAULT_PATTERNS
    ), f"no lab rule message matches any D-002 pattern: {messages}"


def test_the_lab_target_is_external_to_the_outbound_detectors() -> None:
    """Otherwise D-004 and D-005 would skip every lab flow and the run would prove nothing."""
    from aegisnet.domain.detectors.addresses import is_internal

    target = _services()["target"]["networks"]["lab"]["ipv4_address"]
    assert ipaddress.ip_address(target) in LAB_SUBNET
    assert not is_internal(target), "the lab target must look external to the outbound rules"


# ---------------------------------------------------------------- the running side (T-5.5)

CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_a_running_lab_container_is_asked_whether_it_can_reach_anything() -> None:
    """Every other test in this file holds the lab to what it *declares*, and a manifest can be
    wrong in a way a manifest cannot detect (T-5.5).

    `internal: true` tells Docker not to attach a default route. It does not stop the host-side
    bridge address from answering — that took `com.docker.network.bridge.inhibit_ipv4`, and the
    way anyone found out was by running `infra/lab/preflight.py` inside a lab container and
    watching it fail (E-54). Until Chunk 30 nothing ran it except an operator who remembered.

    It is in CI now, and this is what stops it being quietly removed: the assertion is on the
    job existing and on it running the pre-flight *inside a container*, not merely on a job with
    the right name.
    """
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    assert "lab" in workflow["jobs"], "ci.yml no longer runs the lab pre-flight"

    steps = workflow["jobs"]["lab"]["steps"]
    commands = " ".join(str(step.get("run", "")) for step in steps)

    assert "preflight.py" in commands, "the job does not run the pre-flight"
    assert "exec" in commands, "the pre-flight must be asked of a running container, not the host"
    assert "aegisnet_lab" in commands, "the job does not inspect the lab network"
    assert "--profile lab" in commands, "the lab must stay behind its opt-in profile even in CI"
    # Suricata is never pulled: only the target comes up, and it builds from this project's own
    # runtime image. A job that needed a third-party sensor image would be the kind of expensive
    # that gets deleted the first time it is slow.
    assert "up -d --build target" in commands
    assert "suricata" not in commands

    teardown = [step for step in steps if "down" in str(step.get("run", ""))]
    assert teardown and all(step.get("if") == "always()" for step in teardown), (
        "a lab left running after a failed job is a lab nobody tore down"
    )
