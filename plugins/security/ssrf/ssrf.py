"""Server-side request forgery: attacker-controlled input reaching a SSRF sink."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class SsrfPlugin(TaintDetector):
    name: ClassVar[str] = "ssrf"
    rule_id: ClassVar[str] = "ssrf"
    kind: ClassVar[TaintKind] = TaintKind.SSRF
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Server-side request forgery"
