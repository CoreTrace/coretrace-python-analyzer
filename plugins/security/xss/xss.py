"""Cross-site scripting: attacker-controlled input reaching a HTML sink."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class XssPlugin(TaintDetector):
    name: ClassVar[str] = "xss"
    rule_id: ClassVar[str] = "xss"
    kind: ClassVar[TaintKind] = TaintKind.HTML
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Cross-site scripting"
