"""Archive extraction without member checks: a crafted archive with ``../`` members or
absolute paths writes outside the target directory. ``tarfile`` accepts a ``filter``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.model import Call, Instruction, Value
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId

_OPENERS = ("tarfile.open", "tarfile.TarFile", "tarfile.TarFile.open", "zipfile.ZipFile", "zipfile.Path")
_EXTRACTORS = tuple(f"{opener}.{method}" for opener in _OPENERS for method in ("extractall", "extract"))


class UnsafeArchivePlugin(SymbolCallDetector):
    name: ClassVar[str] = "unsafe-archive-extraction"
    rule_id: ClassVar[str] = "unsafe-archive-extraction"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CallGraphAnalysis})
    symbols: ClassVar[frozenset[SymbolId]] = frozenset(
        SymbolId(f"python.{p}") for p in (*_EXTRACTORS, "shutil.unpack_archive")
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    message_template: ClassVar[str] = (
        "call to {symbol} extracts an archive without checking its member paths; a "
        "crafted archive writes outside the target directory"
    )

    def accepts(self, call: Call, symbol: SymbolId, defs: Mapping[Value, Instruction]) -> bool:
        # ``extractall(path, filter="data")`` rejects unsafe members (Python 3.12).
        return not any(name == "filter" for name, _ in call.keywords)
