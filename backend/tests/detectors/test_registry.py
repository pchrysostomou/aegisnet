"""The in-process rule registry."""

from __future__ import annotations

import pytest

from aegisnet.domain.detectors import UnknownRuleError, default_detectors, get_detector

pytestmark = pytest.mark.unit


def test_the_registry_lists_every_shipped_rule_once() -> None:
    specs = [d.spec for d in default_detectors()]
    assert [s.rule_id for s in specs] == ["D-001", "D-002", "D-003", "D-004", "D-005"]
    assert len({s.rule_id for s in specs}) == len(specs) and all(s.version >= 1 for s in specs)
    assert get_detector("D-001").spec == specs[0]
    with pytest.raises(UnknownRuleError):
        get_detector("D-999")
