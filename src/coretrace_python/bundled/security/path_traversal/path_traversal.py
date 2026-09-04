"""Path traversal: attacker-controlled input reaching a PATH sink."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class PathTraversalPlugin(TaintDetector):
    name: ClassVar[str] = "path-traversal"
    rule_id: ClassVar[str] = "path-traversal"
    kind: ClassVar[TaintKind] = TaintKind.PATH
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Path traversal"
