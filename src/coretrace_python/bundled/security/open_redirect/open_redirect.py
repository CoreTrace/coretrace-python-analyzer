"""Open redirect: attacker-controlled input reaching a open redirect sink."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class OpenRedirectPlugin(TaintDetector):
    name: ClassVar[str] = "open-redirect"
    rule_id: ClassVar[str] = "open-redirect"
    kind: ClassVar[TaintKind] = TaintKind.REDIRECT
    severity: ClassVar[Severity] = Severity.MEDIUM
    title: ClassVar[str] = "Open redirect"
