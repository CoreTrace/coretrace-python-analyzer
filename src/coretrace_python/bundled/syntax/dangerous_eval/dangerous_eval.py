"""Report calls to the dynamic-code builtins, whatever name the file gives them."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.findings import RuleDescription, Severity
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId


class DangerousEvalPlugin(SymbolCallDetector):
    name: ClassVar[str] = "dangerous-eval"
    rules: ClassVar[Mapping[str, RuleDescription]] = {
        "dangerous-eval": RuleDescription(
            "Dynamic code execution",
            "A call to eval or exec, whatever name the file gives them.",
        ),
    }
    rule_id: ClassVar[str] = "dangerous-eval"
    symbols: ClassVar[frozenset[SymbolId]] = frozenset(
        {SymbolId("python.builtins.eval"), SymbolId("python.builtins.exec")}
    )
    severity: ClassVar[Severity] = Severity.HIGH
    message_template: ClassVar[str] = "call to {symbol} executes dynamically built code"
