"""Entry points registered away from their definition (architecture §16, §25).

Django views are plain functions listed in ``urls.py``; Flask and FastAPI applications
can register handlers programmatically too. A ``RouteRegistrar`` model names the
registering call and the argument that references the handler. The engine scans every
module of a project for such calls before analysing and provides the result as the
``taint.routes`` input, so a registered function, or the methods of a registered class,
receive attacker-controlled parameters wherever they are defined.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.interprocedural import project_symbol
from coretrace_python.semantic.scopes import ScopeTable
from coretrace_python.semantic.symbols import SymbolId, SymbolTable
from coretrace_python.taint.models import EntryPoint, ModelTable

Routes = Mapping[SymbolId, EntryPoint]


class RegisteredRoutes(Analysis[Routes]):
    """Project symbols registered as handlers, provided by the engine; empty on its own."""

    name: ClassVar[str] = "taint.routes"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> Routes:
        return {}


def registered_routes(
    module: nodes.Module, scopes: ScopeTable, symbols: SymbolTable, models: ModelTable
) -> dict[SymbolId, EntryPoint]:
    """The handlers this module registers, as project symbols, with the entry point the
    registrar grants them."""

    scope = scopes.module_scope.id
    defined = {
        s.name for s in module.body if isinstance(s, nodes.Function | nodes.Class)
    }
    found: dict[SymbolId, EntryPoint] = {}
    for call in _calls(module.body):
        callee = symbols.resolve_expression(scope, call.callee)
        registrar = models.route_registrar(callee) if callee is not None else None
        if registrar is None:
            continue
        handler: nodes.Expression | None = None
        if registrar.argument < len(call.arguments):
            handler = call.arguments[registrar.argument]
        elif registrar.keyword is not None:
            handler = next((k.value for k in call.keywords if k.name == registrar.keyword), None)
        if handler is None:
            continue
        target = _handler_symbol(handler, module, symbols, scope, defined)
        if target is not None:
            found.setdefault(target, EntryPoint(registrar.symbol, registrar.label, registrar.kinds))
    return found


def _handler_symbol(
    handler: nodes.Expression,
    module: nodes.Module,
    symbols: SymbolTable,
    scope: object,
    defined: set[str],
) -> SymbolId | None:
    if isinstance(handler, nodes.Call):
        # ``NoteView.as_view()``: the class is the handler.
        handler = handler.callee
    if isinstance(handler, nodes.Attribute) and handler.name == "as_view":
        handler = handler.value
    symbol = symbols.resolve_expression(scope, handler)  # type: ignore[arg-type]
    if symbol is not None:
        return symbol
    if isinstance(handler, nodes.Name) and handler.identifier in defined:
        return project_symbol(module.name, handler.identifier)
    return None


def _calls(body: tuple[nodes.Statement, ...]) -> Iterator[nodes.Call]:
    for statement in body:
        if isinstance(statement, nodes.Function | nodes.Class):
            continue
        yield from _calls_in(statement)


def _calls_in(node: Node) -> Iterator[nodes.Call]:
    if isinstance(node, nodes.Function | nodes.Class | nodes.Lambda | nodes.Comprehension):
        return
    if isinstance(node, nodes.Call):
        yield node
    for child in children(node):
        yield from _calls_in(child)
