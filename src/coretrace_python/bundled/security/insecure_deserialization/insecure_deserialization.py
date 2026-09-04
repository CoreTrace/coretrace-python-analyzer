"""Insecure deserialization: attacker-controlled input reaching a insecure deserialization sink."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class InsecureDeserializationPlugin(TaintDetector):
    name: ClassVar[str] = "insecure-deserialization"
    rule_id: ClassVar[str] = "insecure-deserialization"
    kind: ClassVar[TaintKind] = TaintKind.DESERIALIZATION
    severity: ClassVar[Severity] = Severity.CRITICAL
    title: ClassVar[str] = "Insecure deserialization"
