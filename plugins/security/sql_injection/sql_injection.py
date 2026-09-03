"""SQL injection: attacker-controlled input reaching a SQL sink."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class SqlInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "sql-injection"
    rule_id: ClassVar[str] = "sql-injection"
    kind: ClassVar[TaintKind] = TaintKind.SQL
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "SQL injection"
