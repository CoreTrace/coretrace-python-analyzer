"""SQL injection: attacker-controlled input reaching a SQL sink."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.findings import RuleDescription, Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class SqlInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "sql-injection"
    rules: ClassVar[Mapping[str, RuleDescription]] = {
        "sql-injection": RuleDescription(
            "SQL injection",
            "Attacker-controlled data reaches a database statement (cursor.execute, SQLAlchemy text, Django raw, ...) rather than a query parameter.",
        ),
    }
    rule_id: ClassVar[str] = "sql-injection"
    kind: ClassVar[TaintKind] = TaintKind.SQL
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "SQL injection"
