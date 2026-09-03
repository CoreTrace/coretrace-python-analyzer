"""Reusable detector bases (architecture §15).

``TaintDetector`` turns the flows of one taint kind into findings; every security
detector is a few class attributes on top of it. ``SymbolCallDetector`` reports calls
whose callee resolves to a canonical symbol, through imports and local aliases alike,
by reading the SSA form.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.ir.model import Call, Symbol
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins.api import Plugin, PluginContext
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TaintAnalysis, TaintKind


class TaintDetector(Plugin):
    """Report every taint flow carrying ``kind`` into a sink."""

    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({TaintAnalysis})
    rule_id: ClassVar[str]
    kind: ClassVar[TaintKind]
    severity: ClassVar[Severity]
    title: ClassVar[str]

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for function in ctx.functions():
            for flow in ctx.get(TaintAnalysis, function).flows:
                if not flow.kinds & self.kind:
                    continue
                message = f"{self.title}: {flow.source.label} input reaches {flow.sink.symbol}"
                metadata = {
                    "source": str(flow.source.symbol),
                    "source_label": flow.source.label,
                    "sink": str(flow.sink.symbol),
                }
                if flow.through is not None and flow.sink_location is not None:
                    message += f" through {flow.through}"
                    metadata["through"] = flow.through
                    metadata["sink_line"] = str(flow.sink_location.start_line)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=message,
                        severity=self.severity,
                        confidence=Confidence.HIGH,
                        span=flow.location,
                        function=function.name,
                        metadata=metadata,
                    )
                )
        return findings


class SymbolCallDetector(Plugin):
    """Report calls whose callee is one of ``symbols``, whatever name the file uses."""

    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis})
    rule_id: ClassVar[str]
    symbols: ClassVar[frozenset[SymbolId]]
    severity: ClassVar[Severity]
    message_template: ClassVar[str]

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for function in ctx.functions():
            ssa = ctx.get(SSAAnalysis, function)
            defined = {
                i.result: i.symbol_id
                for block in ssa.blocks
                for i in block.instructions
                if isinstance(i, Symbol)
            }
            for block in ssa.blocks:
                for instruction in block.instructions:
                    if not isinstance(instruction, Call):
                        continue
                    symbol = defined.get(instruction.callee)
                    if symbol is None or symbol not in self.symbols:
                        continue
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            message=self.message_template.format(symbol=symbol),
                            severity=self.severity,
                            confidence=Confidence.HIGH,
                            span=instruction.location,
                            function=function.name,
                            metadata={"symbol": str(symbol)},
                        )
                    )
        return findings
