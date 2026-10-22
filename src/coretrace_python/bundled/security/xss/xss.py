"""Cross-site scripting: attacker-controlled input reaching a HTML sink."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.findings import RuleDescription, Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class XssPlugin(TaintDetector):
    name: ClassVar[str] = "xss"
    rules: ClassVar[Mapping[str, RuleDescription]] = {
        "xss": RuleDescription(
            "Cross-site scripting",
            "Attacker-controlled data reaches an HTTP response body built without escaping.",
        ),
    }
    rule_id: ClassVar[str] = "xss"
    kind: ClassVar[TaintKind] = TaintKind.HTML
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Cross-site scripting"
