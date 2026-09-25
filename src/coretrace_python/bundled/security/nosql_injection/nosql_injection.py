"""NoSQL injection: attacker input that may hold a structure reaching a NOSQL sink, such
as a MongoDB filter, where a JSON body giving ``{"$ne": null}`` matches any value. Text
input carries no ``NOSQL``: a string cannot hold an operator. The engine ships no NOSQL
sink; model plugins declare them."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class NoSqlInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "nosql-injection"
    rule_id: ClassVar[str] = "nosql-injection"
    kind: ClassVar[TaintKind] = TaintKind.NOSQL
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "NoSQL injection"
