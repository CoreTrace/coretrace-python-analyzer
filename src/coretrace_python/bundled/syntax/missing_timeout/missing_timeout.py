"""HTTP client calls without a ``timeout``: a slow or silent peer blocks the caller."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Confidence, Finding, RuleDescription, Severity
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.model import Call
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import Plugin, PluginContext
from coretrace_python.semantic.symbols import SymbolId

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "request")
_CALLERS = ("requests", "requests.Session", "requests.api", "httpx", "httpx.Client", "httpx.AsyncClient")
HTTP_CALLS = frozenset(SymbolId(f"python.{caller}.{method}") for caller in _CALLERS for method in _METHODS)


class MissingTimeoutPlugin(Plugin):
    name: ClassVar[str] = "missing-timeout"
    rules: ClassVar[Mapping[str, RuleDescription]] = {
        "missing-timeout": RuleDescription(
            "HTTP request without a timeout",
            "A Requests or httpx call without a timeout, which can wait forever.",
        ),
    }
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CallGraphAnalysis})

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        graph = ctx.get(CallGraphAnalysis)
        findings: list[Finding] = []
        for function in ctx.functions():
            symbols = graph.symbols(graph.name_of(function))
            for block in ctx.get(SSAAnalysis, function).blocks:
                for instruction in block.instructions:
                    if not isinstance(instruction, Call):
                        continue
                    symbol = symbols.get(instruction.callee)
                    if symbol is None or symbol not in HTTP_CALLS:
                        continue
                    if any(name == "timeout" for name, _ in instruction.keywords):
                        continue
                    findings.append(
                        Finding(
                            "missing-timeout",
                            f"{symbol} is called without a timeout; a slow or silent peer "
                            "blocks this code indefinitely",
                            Severity.LOW,
                            Confidence.HIGH,
                            instruction.location,
                            function.name,
                            {"symbol": str(symbol)},
                        )
                    )
        return findings
