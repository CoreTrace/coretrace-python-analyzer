"""Report calls to the dynamic-code builtins, whatever name the file gives them."""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.plugins import Plugin, PluginContext
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeId, ScopeTable
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId

DANGEROUS = frozenset({SymbolId("python.builtins.eval"), SymbolId("python.builtins.exec")})


class DangerousEvalPlugin(Plugin):
    name: ClassVar[str] = "dangerous-eval"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({ScopeAnalysis, SymbolAnalysis})

    def analyze(self, ctx: PluginContext) -> list[Finding]:
        scopes = ctx.get(ScopeAnalysis)
        symbols = ctx.get(SymbolAnalysis)
        findings: list[Finding] = []
        for function in ctx.functions():
            for call, scope_id, enclosing in _calls(function, scopes, scopes.scope_for(function).id):
                if not isinstance(call.callee, nodes.Name):
                    continue
                symbol = symbols.resolve(scope_id, call.callee.identifier)
                if symbol in DANGEROUS:
                    findings.append(
                        Finding(
                            rule_id="dangerous-eval",
                            message=f"call to {symbol} executes dynamically built code",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            span=call.span,
                            function=enclosing,
                        )
                    )
        return findings


def _calls(
    function: nodes.Function, scopes: ScopeTable, scope_id: ScopeId
) -> Iterator[tuple[nodes.Call, ScopeId, str]]:
    """Yield every call in ``function`` with the scope it is evaluated in."""

    def walk(node: Node, scope_id: ScopeId, enclosing: str) -> Iterator[tuple[nodes.Call, ScopeId, str]]:
        if isinstance(node, nodes.Call):
            yield node, scope_id, enclosing
        if isinstance(node, nodes.Function):
            scope_id, enclosing = scopes.scope_for(node).id, node.name
        elif isinstance(node, nodes.Class | nodes.Comprehension):
            scope_id = scopes.scope_for(node).id
        for child in children(node):
            yield from walk(child, scope_id, enclosing)

    for statement in function.body:
        yield from walk(statement, scope_id, function.name)
