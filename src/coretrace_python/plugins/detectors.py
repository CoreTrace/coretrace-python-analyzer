"""Reusable detector bases (architecture §15).

``TaintDetector`` turns the flows of one taint kind into findings; every security
detector is a few class attributes on top of it. ``SymbolCallDetector`` reports calls
whose callee resolves to a canonical symbol, through imports and local aliases alike,
by reading the SSA form.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.findings.refutation import RefutationAnalysis, Status, Verdict
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.model import Call, Instruction, Symbol, Value
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins.api import Plugin, PluginContext
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TaintAnalysis, TaintFlow, TaintKind


class TaintDetector(Plugin):
    """Report every taint flow carrying ``kind`` into a sink."""

    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({TaintAnalysis, RefutationAnalysis})
    rule_id: ClassVar[str]
    kind: ClassVar[TaintKind]
    severity: ClassVar[Severity]
    title: ClassVar[str]
    confidence: ClassVar[Confidence] = Confidence.HIGH

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for function in ctx.functions():
            verdicts = ctx.get(RefutationAnalysis, function)
            for flow in ctx.get(TaintAnalysis, function).flows:
                if not flow.kinds & self.kind:
                    continue
                verdict = verdicts.verdict(flow)
                if verdict.status is Status.REFUTED:
                    continue
                verdict = self.judge(ctx, function, flow, verdict)
                if verdict.status is Status.REFUTED:
                    continue
                message = f"{self.title}: {flow.source.label} input reaches {flow.sink.symbol}"
                metadata = {
                    "source": str(flow.source.symbol),
                    "source_label": flow.source.label,
                    "sink": str(flow.sink.symbol),
                    "verdict": verdict.status.value,
                    "evidence": verdict.evidence,
                }
                if flow.through is not None and flow.sink_location is not None:
                    message += f" through {flow.through}"
                    metadata["through"] = flow.through
                    metadata["sink_line"] = str(flow.sink_location.start_line)
                confidence = (
                    self.confidence if verdict.status is Status.VULNERABILITY else _lower(self.confidence)
                )
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=message,
                        severity=self.severity,
                        confidence=confidence,
                        span=flow.location,
                        function=function.name,
                        metadata=metadata,
                    )
                )
        return findings

    def judge(self, ctx: PluginContext, function: nodes.Function, flow: TaintFlow, verdict: Verdict) -> Verdict:
        """This rule's verdict on ``flow``, given the refutation's: the same, unless the rule
        knows more about its own sinks. The refutation's verdict, which other consumers
        of the flow read, does not change."""

        return verdict


def _lower(confidence: Confidence) -> Confidence:
    return {Confidence.HIGH: Confidence.MEDIUM}.get(confidence, Confidence.LOW)


class SymbolCallDetector(Plugin):
    """Report calls whose callee is one of ``symbols``, whatever name the file uses.
    A subclass that also requires ``CallGraphAnalysis`` sees derived call-chain symbols
    too (``tarfile.open(p).extractall`` is ``tarfile.open.extractall``); ``accepts``
    lets it keep only some calls, such as those with a given keyword."""

    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis})
    rule_id: ClassVar[str]
    symbols: ClassVar[frozenset[SymbolId]]
    severity: ClassVar[Severity]
    message_template: ClassVar[str]
    confidence: ClassVar[Confidence] = Confidence.HIGH

    def accepts(self, call: Call, symbol: SymbolId, defs: Mapping[Value, Instruction]) -> bool:
        return True

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        graph = ctx.get(CallGraphAnalysis) if CallGraphAnalysis in self.requires else None
        for function in ctx.functions():
            ssa = ctx.get(SSAAnalysis, function)
            defs: dict[Value, Instruction] = {
                i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None
            }
            symbols: Mapping[Value, SymbolId]
            if graph is not None:
                symbols = graph.symbols(graph.name_of(function))
            else:
                symbols = {v: i.symbol_id for v, i in defs.items() if isinstance(i, Symbol)}
            for block in ssa.blocks:
                for instruction in block.instructions:
                    if not isinstance(instruction, Call):
                        continue
                    symbol = symbols.get(instruction.callee)
                    if symbol is None or symbol not in self.symbols:
                        continue
                    if not self.accepts(instruction, symbol, defs):
                        continue
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            message=self.message_template.format(symbol=symbol),
                            severity=self.severity,
                            confidence=self.confidence,
                            span=instruction.location,
                            function=function.name,
                            metadata={"symbol": str(symbol)},
                        )
                    )
        return findings
