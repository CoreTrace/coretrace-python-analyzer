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
    for call, callee in _registration_calls(module, scopes, symbols):
        registrar = models.route_registrar(callee)
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


def _registration_calls(
    module: nodes.Module, scopes: ScopeTable, symbols: SymbolTable
) -> Iterator[tuple[nodes.Call, SymbolId]]:
    """Every call of the module with a resolvable callee: at module level, and inside
    functions such as ``def setup_routes(app: Application)``, where a call on an
    annotated parameter denotes the class's method (``app.router.add_route``)."""

    module_scope = scopes.module_scope.id
    for call in _calls(module.body):
        callee = symbols.resolve_expression(module_scope, call.callee)
        if callee is not None:
            yield call, callee
    for function in _functions(module.body):
        scope = scopes.scope_for(function)
        enclosing = scope.parent if scope.parent is not None else scope.id
        annotated: dict[str, SymbolId] = {}
        for parameter in function.parameters:
            if parameter.annotation is not None:
                symbol = symbols.resolve_expression(enclosing, parameter.annotation)
                if symbol is not None:
                    annotated[parameter.name] = symbol
        for call in _calls(function.body):
            callee = symbols.resolve_expression(scope.id, call.callee)
            if callee is None:
                callee = _through_annotation(call.callee, annotated)
            if callee is not None:
                yield call, callee


def _through_annotation(expression: nodes.Expression, annotated: Mapping[str, SymbolId]) -> SymbolId | None:
    """``app.router.add_route`` with ``app: Application`` is ``Application.router.add_route``."""

    names: list[str] = []
    while isinstance(expression, nodes.Attribute):
        names.append(expression.name)
        expression = expression.value
    if not isinstance(expression, nodes.Name) or expression.identifier not in annotated:
        return None
    symbol = annotated[expression.identifier]
    for name in reversed(names):
        symbol = symbol.attribute(name)
    return symbol


def _functions(body: tuple[nodes.Statement, ...]) -> Iterator[nodes.Function]:
    for statement in body:
        if isinstance(statement, nodes.Function):
            yield statement
        elif isinstance(statement, nodes.Class):
            yield from (member for member in statement.body if isinstance(member, nodes.Function))


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
