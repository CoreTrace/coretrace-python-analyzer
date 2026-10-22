"""Insecure deserialization: attacker-controlled input reaching a insecure deserialization sink."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.findings import RuleDescription, Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class InsecureDeserializationPlugin(TaintDetector):
    name: ClassVar[str] = "insecure-deserialization"
    rules: ClassVar[Mapping[str, RuleDescription]] = {
        "insecure-deserialization": RuleDescription(
            "Insecure deserialization",
            "Attacker-controlled data reaches a deserializer that can build arbitrary objects or run code: pickle, marshal, dill, jsonpickle, shelve, or a YAML loader without a safe loader.",
        ),
    }
    rule_id: ClassVar[str] = "insecure-deserialization"
    kind: ClassVar[TaintKind] = TaintKind.DESERIALIZATION
    severity: ClassVar[Severity] = Severity.CRITICAL
    title: ClassVar[str] = "Insecure deserialization"
