"""``app.run(debug=True)``: the Werkzeug debugger executes code on any exception."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.plugins import Plugin, PluginContext
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeId, ScopeTable
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId

RUN = SymbolId("python.flask.Flask.run")


class FlaskDebugPlugin(Plugin):
    name: ClassVar[str] = "flask-debug"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({ScopeAnalysis, SymbolAnalysis})

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        scopes = ctx.get(ScopeAnalysis)
        symbols = ctx.get(SymbolAnalysis)
        findings: list[Finding] = []
        for call, scope, function in _calls(ctx.module.body, scopes, scopes.module_scope.id, None):
            if symbols.resolve_expression(scope, call.callee) != RUN:
                continue
            if not any(
                k.name == "debug" and isinstance(k.value, nodes.Constant) and k.value.value is True
                for k in call.keywords
            ):
                continue
            findings.append(
                Finding(
                    "debug-enabled",
                    "Flask debugger enabled: app.run(debug=True) exposes an interactive "
                    "debugger able to execute Python on any exception",
                    Severity.HIGH,
                    Confidence.HIGH,
                    call.span,
                    function,
                    {"symbol": str(RUN)},
                )
            )
        return findings


def _calls(
    body: Sequence[Node], scopes: ScopeTable, scope: ScopeId, function: str | None
) -> Iterator[tuple[nodes.Call, ScopeId, str | None]]:
    for node in body:
        if isinstance(node, nodes.Function):
            yield from _calls(node.body, scopes, scopes.scope_for(node).id, node.name)
        elif isinstance(node, nodes.Class):
            yield from _calls(node.body, scopes, scopes.scope_for(node).id, None)
        elif isinstance(node, nodes.Lambda | nodes.Comprehension):
            continue
        else:
            if isinstance(node, nodes.Call):
                yield node, scope, function
            yield from _calls(list(children(node)), scopes, scope, function)
