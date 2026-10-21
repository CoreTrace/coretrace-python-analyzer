"""What an annotation binds in the scope it stands in.

An annotation evaluated when its definition runs binds the targets of its assignment
expressions there, as any expression does. Its lambdas and comprehensions introduce
scopes of their own, which keep their bindings.
"""

from __future__ import annotations

from coretrace_python.frontend import build_hir
from coretrace_python.semantic.scopes import BindingKind, Scope, ScopeTable, analyze_scopes
from coretrace_python.source import SourceManager

POSTPONED = "from __future__ import annotations\n\n"


def analyze(text: str) -> ScopeTable:
    return analyze_scopes(build_hir(SourceManager().add_source("app.py", text)))


def child(scopes: ScopeTable, parent: Scope, name: str) -> Scope:
    (found,) = (scope for scope in scopes.children(parent.id) if scope.name == name)
    return found


def test_an_evaluated_parameter_annotation_binds_where_the_function_is_defined() -> None:
    scopes = analyze("def f(x: [(found := i) for i in (1,)]):\n    pass\n")

    assert scopes.module_scope.bindings["found"].kind is BindingKind.LOCAL


def test_an_evaluated_parameter_annotation_binds_in_the_enclosing_function() -> None:
    scopes = analyze("def outer():\n    def inner(x: [(found := i) for i in (1,)]):\n        pass\n")

    assert "found" in child(scopes, scopes.module_scope, "outer").bindings
    assert "found" not in scopes.module_scope.bindings


def test_a_lambda_in_a_postponed_annotation_keeps_its_own_bindings() -> None:
    scopes = analyze(POSTPONED + "def f(x: (lambda: (inner := 1))):\n    pass\n")

    assert "inner" in child(scopes, scopes.module_scope, "<lambda>").bindings
    assert "inner" not in scopes.module_scope.bindings
