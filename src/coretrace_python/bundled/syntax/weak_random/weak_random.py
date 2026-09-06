"""``random`` builds a secret: the Mersenne Twister is predictable from a few outputs, so
a token, key or session identifier drawn from it can be guessed. ``secrets`` and
``random.SystemRandom`` are the alternatives. A call is reported when its result is
assigned to a credential-like name, or when the enclosing function's name says it
produces one."""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.plugins import Plugin, PluginContext
from coretrace_python.semantic.scopes import ScopeAnalysis
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId

_FUNCTIONS = ("random", "randint", "choice", "choices", "randrange", "getrandbits", "uniform", "sample", "randbytes")
RANDOM = frozenset(SymbolId(f"python.random.{f}") for f in _FUNCTIONS)
CREDENTIAL = re.compile(r"(?i)(token|secret|password|passwd|api_?key|session|nonce|salt|otp|csrf|auth)")


class WeakRandomPlugin(Plugin):
    name: ClassVar[str] = "weak-random"
    rule_id: ClassVar[str] = "weak-random"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({ScopeAnalysis, SymbolAnalysis})

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        scopes = ctx.get(ScopeAnalysis)
        symbols = ctx.get(SymbolAnalysis)
        findings: list[Finding] = []
        for function in ctx.functions():
            scope = scopes.scope_for(function).id
            for target, call in _random_calls(function, scope, symbols):
                purpose = target if target is not None and CREDENTIAL.search(target) else None
                if purpose is None and CREDENTIAL.search(function.name):
                    purpose = function.name
                if purpose is None:
                    continue
                symbol = symbols.resolve_expression(scope, call.callee)
                findings.append(
                    Finding(
                        self.rule_id,
                        f"{symbol} is not a secure random source; {purpose!r} looks like a secret",
                        Severity.MEDIUM,
                        Confidence.MEDIUM,
                        call.span,
                        function.name,
                        {"symbol": str(symbol), "purpose": purpose},
                    )
                )
        return findings


def _random_calls(
    function: nodes.Function, scope: object, symbols: object
) -> Iterator[tuple[str | None, nodes.Call]]:
    """Calls to ``random`` functions with the name of the target they are assigned to."""

    def walk(node: Node, target: str | None) -> Iterator[tuple[str | None, nodes.Call]]:
        if isinstance(node, nodes.Function | nodes.Class | nodes.Lambda):
            return
        if isinstance(node, nodes.Assign | nodes.AugAssign):
            target = _target_name(node.target)
        if isinstance(node, nodes.Call):
            symbol = symbols.resolve_expression(scope, node.callee)  # type: ignore[attr-defined]
            if symbol in RANDOM:
                yield target, node
        for child in children(node):
            yield from walk(child, target)

    for statement in function.body:
        yield from walk(statement, None)


def _target_name(target: nodes.Target) -> str | None:
    if isinstance(target, nodes.Name):
        return target.identifier
    if isinstance(target, nodes.Attribute):
        return target.name
    if isinstance(target, nodes.Subscript) and isinstance(target.key, nodes.Constant):
        return str(target.key.value)
    return None
