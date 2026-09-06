"""``tempfile.mktemp`` returns a name without creating the file: another process can
create it first. ``mkstemp``, ``NamedTemporaryFile`` and ``TemporaryDirectory`` are safe."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId


class InsecureTempFilePlugin(SymbolCallDetector):
    name: ClassVar[str] = "insecure-temp-file"
    rule_id: ClassVar[str] = "insecure-temp-file"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CallGraphAnalysis})
    symbols: ClassVar[frozenset[SymbolId]] = frozenset({SymbolId("python.tempfile.mktemp")})
    severity: ClassVar[Severity] = Severity.MEDIUM
    message_template: ClassVar[str] = (
        "call to {symbol} names a temporary file without creating it; use mkstemp or "
        "NamedTemporaryFile"
    )
