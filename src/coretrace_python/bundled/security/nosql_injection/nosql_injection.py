"""NoSQL injection: attacker input that may hold a structure reaching a NOSQL sink, such
as a MongoDB filter, where a JSON body giving ``{"$ne": null}`` matches any value. Text
input carries no ``NOSQL``: a string cannot hold an operator. The engine ships no NOSQL
sink; model plugins declare them."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.findings import RuleDescription, Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class NoSqlInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "nosql-injection"
    rules: ClassVar[Mapping[str, RuleDescription]] = {
        "nosql-injection": RuleDescription(
            "NoSQL injection",
            "Attacker input that may hold a structure, such as a JSON body, reaches a NoSQL query, where an operator such as {\"$ne\": null} matches any value.",
        ),
    }
    rule_id: ClassVar[str] = "nosql-injection"
    kind: ClassVar[TaintKind] = TaintKind.NOSQL
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "NoSQL injection"
