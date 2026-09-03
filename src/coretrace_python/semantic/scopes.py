"""Lexical scope analysis over PyHIR (architecture §4.1).

Python decides where a name lives per scope, not per statement: any binding anywhere in
a function makes the name local to the whole function, ``global`` and ``nonlocal``
redirect a name to another scope, class bodies are invisible to the functions they
contain, and comprehensions get a scope of their own. The analysis therefore runs in
two passes: collect every binding of every scope, then resolve names against the
finished tree.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext
from coretrace_python.hir import nodes
from coretrace_python.source import SourceSpan


class ScopeKind(Enum):
    MODULE = "module"
    FUNCTION = "function"
    CLASS = "class"
    COMPREHENSION = "comprehension"


class BindingKind(Enum):
    PARAMETER = "parameter"
    LOCAL = "local"
    IMPORT = "import"
    FUNCTION = "function"
    CLASS = "class"
    GLOBAL = "global"
    NONLOCAL = "nonlocal"


class ResolutionKind(Enum):
    LOCAL = "local"
    FREE = "free"
    GLOBAL = "global"
    UNBOUND = "unbound"


_REDIRECTIONS = frozenset({BindingKind.GLOBAL, BindingKind.NONLOCAL})


class ScopeError(Exception):
    """A source-located scoping rule violation, such as an invalid ``nonlocal``."""


@dataclass(frozen=True, order=True)
class ScopeId:
    """Stable identity of a scope: source ID, then ``name#ordinal`` per nesting level."""

    value: str

    def child(self, name: str, ordinal: int) -> ScopeId:
        return ScopeId(f"{self.value}::{name}#{ordinal}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Binding:
    name: str
    kind: BindingKind
    span: SourceSpan


@dataclass(frozen=True)
class Scope:
    id: ScopeId
    kind: ScopeKind
    name: str
    parent: ScopeId | None
    span: SourceSpan
    bindings: Mapping[str, Binding]


@dataclass(frozen=True)
class Resolution:
    kind: ResolutionKind
    scope: ScopeId | None


class ScopeTable:
    """Immutable scope tree with Python name resolution."""

    def __init__(self, scopes: tuple[Scope, ...], spans: Mapping[SourceSpan, ScopeId]) -> None:
        self._scopes: Mapping[ScopeId, Scope] = MappingProxyType({s.id: s for s in scopes})
        children: dict[ScopeId, list[Scope]] = {scope.id: [] for scope in scopes}
        for scope in scopes:
            if scope.parent is not None:
                children[scope.parent].append(scope)
        self._children: Mapping[ScopeId, tuple[Scope, ...]] = MappingProxyType(
            {scope_id: tuple(found) for scope_id, found in children.items()}
        )
        self._spans = MappingProxyType(dict(spans))
        self._module = scopes[0]

    @property
    def module_scope(self) -> Scope:
        return self._module

    def scope(self, scope_id: ScopeId) -> Scope:
        return self._scopes[scope_id]

    def children(self, scope_id: ScopeId) -> tuple[Scope, ...]:
        return self._children[scope_id]

    def scope_for(self, node: nodes.Function | nodes.Class | nodes.Comprehension) -> Scope:
        """Return the scope introduced by a definition or comprehension node."""

        return self._scopes[self._spans[node.span]]

    def resolve(self, scope_id: ScopeId, name: str) -> Resolution:
        scope = self.scope(scope_id)
        binding = scope.bindings.get(name)
        if binding is not None:
            if binding.kind is BindingKind.GLOBAL:
                return self._global(name)
            if binding.kind is BindingKind.NONLOCAL:
                target = self._enclosing_function_binding(scope, name)
                assert target is not None, "validated at construction"
                return Resolution(ResolutionKind.FREE, target)
            if scope.kind is ScopeKind.MODULE:
                return Resolution(ResolutionKind.GLOBAL, scope.id)
            return Resolution(ResolutionKind.LOCAL, scope.id)

        current = self._parent(scope)
        while current is not None:
            if current.kind is ScopeKind.MODULE:
                return self._global(name)
            if current.kind is not ScopeKind.CLASS:
                enclosing = current.bindings.get(name)
                if enclosing is not None and enclosing.kind is BindingKind.GLOBAL:
                    return self._global(name)
                if enclosing is not None and enclosing.kind is not BindingKind.NONLOCAL:
                    return Resolution(ResolutionKind.FREE, current.id)
            current = self._parent(current)
        return Resolution(ResolutionKind.UNBOUND, None)

    def _global(self, name: str) -> Resolution:
        if name in self._module.bindings:
            return Resolution(ResolutionKind.GLOBAL, self._module.id)
        return Resolution(ResolutionKind.UNBOUND, None)

    def _parent(self, scope: Scope) -> Scope | None:
        return None if scope.parent is None else self._scopes[scope.parent]

    def _enclosing_function_binding(self, scope: Scope, name: str) -> ScopeId | None:
        current = self._parent(scope)
        while current is not None and current.kind is not ScopeKind.MODULE:
            if current.kind is ScopeKind.FUNCTION:
                binding = current.bindings.get(name)
                if binding is not None and binding.kind not in _REDIRECTIONS:
                    return current.id
            current = self._parent(current)
        return None


# --------------------------------------------------------------------------- construction


class _ScopeBuilder:
    def __init__(
        self,
        scope_id: ScopeId,
        kind: ScopeKind,
        name: str,
        parent: _ScopeBuilder | None,
        span: SourceSpan,
    ) -> None:
        self.id = scope_id
        self.kind = kind
        self.name = name
        self.parent = parent
        self.span = span
        self.bindings: dict[str, Binding] = {}
        self.child_count = 0
        self.declarations: list[tuple[nodes.Nonlocal, str]] = []

    def bind(self, name: str, kind: BindingKind, span: SourceSpan) -> None:
        existing = self.bindings.get(name)
        if existing is None:
            self.bindings[name] = Binding(name, kind, span)
        elif kind in (BindingKind.GLOBAL, BindingKind.NONLOCAL):
            # Declarations win over ordinary bindings regardless of statement order.
            self.bindings[name] = Binding(name, kind, span)

    def child(self, kind: ScopeKind, name: str, span: SourceSpan) -> _ScopeBuilder:
        builder = _ScopeBuilder(self.id.child(name, self.child_count), kind, name, self, span)
        self.child_count += 1
        return builder

    def freeze(self) -> Scope:
        return Scope(
            id=self.id,
            kind=self.kind,
            name=self.name,
            parent=None if self.parent is None else self.parent.id,
            span=self.span,
            bindings=MappingProxyType(dict(self.bindings)),
        )


_COMPREHENSION_NAMES = {"list": "<listcomp>", "set": "<setcomp>", "generator": "<genexpr>"}


class _Collector:
    def __init__(self, module: nodes.Module) -> None:
        self.module = _ScopeBuilder(
            ScopeId(str(module.span.source_id)), ScopeKind.MODULE, "<module>", None, module.span
        )
        self.builders: list[_ScopeBuilder] = [self.module]
        self.spans: dict[SourceSpan, ScopeId] = {}
        self.body(module.body, self.module)

    def body(self, statements: tuple[nodes.Statement, ...], scope: _ScopeBuilder) -> None:
        for statement in statements:
            self.statement(statement, scope)

    def statement(self, node: nodes.Statement, scope: _ScopeBuilder) -> None:
        if isinstance(node, nodes.Assign | nodes.AugAssign):
            self.expression(node.value, scope)
            self.target(node.target, scope)
        elif isinstance(node, nodes.Assert):
            self.expression(node.test, scope)
            if node.message is not None:
                self.expression(node.message, scope)
        elif isinstance(node, nodes.With):
            for item in node.items:
                self.expression(item.context, scope)
                if item.target is not None:
                    scope.bind(item.target.identifier, BindingKind.LOCAL, item.target.span)
            self.body(node.body, scope)
        elif isinstance(node, nodes.Try):
            self.body(node.body, scope)
            for handler in node.handlers:
                if handler.type is not None:
                    self.expression(handler.type, scope)
                if handler.name is not None:
                    scope.bind(handler.name, BindingKind.LOCAL, handler.span)
                self.body(handler.body, scope)
            self.body(node.orelse, scope)
            self.body(node.finalbody, scope)
        elif isinstance(node, nodes.EnterWith | nodes.ExitWith | nodes.EnterHandler):
            pass
        elif isinstance(node, nodes.Return):
            if node.value is not None:
                self.expression(node.value, scope)
        elif isinstance(node, nodes.ExpressionStatement):
            self.expression(node.expression, scope)
        elif isinstance(node, nodes.Import):
            for alias in node.names:
                local_name = alias.as_name or alias.name.partition(".")[0]
                scope.bind(local_name, BindingKind.IMPORT, alias.span)
        elif isinstance(node, nodes.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    scope.bind(alias.as_name or alias.name, BindingKind.IMPORT, alias.span)
        elif isinstance(node, nodes.Global):
            if scope.kind is not ScopeKind.MODULE:
                for name in node.names:
                    scope.bind(name, BindingKind.GLOBAL, node.span)
                    self.module.bind(name, BindingKind.LOCAL, node.span)
        elif isinstance(node, nodes.Nonlocal):
            if scope.kind is ScopeKind.MODULE:
                raise ScopeError(f"{node.span.display()}: nonlocal declaration at module level")
            for name in node.names:
                scope.bind(name, BindingKind.NONLOCAL, node.span)
                scope.declarations.append((node, name))
        elif isinstance(node, nodes.Function):
            for decorator in node.decorators:
                self.expression(decorator, scope)
            for parameter in node.parameters:
                if parameter.default is not None:
                    self.expression(parameter.default, scope)
            scope.bind(node.name, BindingKind.FUNCTION, node.span)
            function = self.open(scope, ScopeKind.FUNCTION, node.name, node.span)
            for parameter in node.parameters:
                function.bind(parameter.name, BindingKind.PARAMETER, parameter.span)
            self.body(node.body, function)
        elif isinstance(node, nodes.Class):
            for decorator in node.decorators:
                self.expression(decorator, scope)
            for base in node.bases:
                self.expression(base, scope)
            scope.bind(node.name, BindingKind.CLASS, node.span)
            self.body(node.body, self.open(scope, ScopeKind.CLASS, node.name, node.span))
        elif isinstance(node, nodes.If):
            self.expression(node.condition, scope)
            self.body(node.body, scope)
            self.body(node.orelse, scope)
        elif isinstance(node, nodes.While):
            self.expression(node.condition, scope)
            self.body(node.body, scope)
        elif isinstance(node, nodes.For):
            self.expression(node.iterable, scope)
            scope.bind(node.target.identifier, BindingKind.LOCAL, node.target.span)
            self.body(node.body, scope)
        elif isinstance(node, nodes.Raise):
            if node.exception is not None:
                self.expression(node.exception, scope)
        elif not isinstance(node, nodes.Pass | nodes.Break | nodes.Continue):
            raise TypeError(f"unknown statement: {node!r}")

    def expression(self, node: nodes.Expression, scope: _ScopeBuilder) -> None:
        if isinstance(node, (nodes.Name, nodes.Constant)):
            return
        if isinstance(node, (nodes.BinaryOp, nodes.Compare)):
            self.expression(node.left, scope)
            self.expression(node.right, scope)
        elif isinstance(node, nodes.UnaryOp):
            self.expression(node.operand, scope)
        elif isinstance(node, nodes.Attribute):
            self.expression(node.value, scope)
        elif isinstance(node, nodes.Subscript):
            self.expression(node.value, scope)
            self.expression(node.key, scope)
        elif isinstance(node, nodes.Call):
            self.expression(node.callee, scope)
            for argument in node.arguments:
                self.expression(argument, scope)
            for keyword in node.keywords:
                self.expression(keyword.value, scope)
        elif isinstance(node, nodes.Comprehension):
            self.comprehension(node, scope)
        elif isinstance(node, nodes.BoolOp):
            for value in node.values:
                self.expression(value, scope)
        elif isinstance(node, nodes.Await):
            self.expression(node.value, scope)
        elif isinstance(node, nodes.Yield):
            if node.value is not None:
                self.expression(node.value, scope)
        elif isinstance(node, nodes.Tuple | nodes.List):
            for element in node.elements:
                self.expression(element, scope)
        elif isinstance(node, nodes.Dict):
            for key, value in node.items:
                self.expression(key, scope)
                self.expression(value, scope)
        else:
            raise TypeError(f"unknown expression: {node!r}")

    def target(self, node: nodes.Target, scope: _ScopeBuilder) -> None:
        if isinstance(node, nodes.Name):
            scope.bind(node.identifier, BindingKind.LOCAL, node.span)
        elif isinstance(node, nodes.Tuple):
            for element in node.elements:
                assert isinstance(element, nodes.Name | nodes.Attribute | nodes.Subscript | nodes.Tuple)
                self.target(element, scope)
        else:
            self.expression(node, scope)

    def comprehension(self, node: nodes.Comprehension, scope: _ScopeBuilder) -> None:
        # The first iterable is evaluated in the enclosing scope; everything else runs
        # inside the comprehension's own scope.
        self.expression(node.generators[0].iterable, scope)
        inner = self.open(scope, ScopeKind.COMPREHENSION, _COMPREHENSION_NAMES[node.kind], node.span)
        for index, generator in enumerate(node.generators):
            if index:
                self.expression(generator.iterable, inner)
            inner.bind(generator.target.identifier, BindingKind.LOCAL, generator.target.span)
            for condition in generator.conditions:
                self.expression(condition, inner)
        self.expression(node.element, inner)

    def open(
        self, parent: _ScopeBuilder, kind: ScopeKind, name: str, span: SourceSpan
    ) -> _ScopeBuilder:
        builder = parent.child(kind, name, span)
        self.builders.append(builder)
        self.spans[span] = builder.id
        return builder


def analyze_scopes(module: nodes.Module) -> ScopeTable:
    """Build the scope tree of ``module`` and validate its declarations."""

    collector = _Collector(module)
    analysis = ScopeTable(
        tuple(builder.freeze() for builder in collector.builders), collector.spans
    )
    for builder in collector.builders:
        for declaration, name in builder.declarations:
            scope = analysis.scope(builder.id)
            if analysis._enclosing_function_binding(scope, name) is None:
                raise ScopeError(
                    f"{declaration.span.display()}: no binding for nonlocal {name!r}"
                )
    return analysis


class ScopeAnalysis(Analysis[ScopeTable]):
    name: ClassVar[str] = "semantic.scopes"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> ScopeTable:
        return analyze_scopes(ctx.module)
