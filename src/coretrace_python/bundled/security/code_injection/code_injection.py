"""Code injection: attacker-controlled input reaching a CODE sink, such as the code
``eval`` or ``exec`` runs. ``dangerous-eval`` reports every such call; this rule reports
the ones attacker input reaches."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class CodeInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "code-injection"
    rule_id: ClassVar[str] = "code-injection"
    kind: ClassVar[TaintKind] = TaintKind.CODE
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Code injection"
