"""What an annotation binds in the scope it stands in.

Python's compiler declares the target of an assignment expression in an annotation
where the annotation stands, whether it is evaluated or not: in a function, the name is
a local of the function. A module's names exist only once assigned, so an annotation
that is never evaluated there, under ``from __future__ import annotations`` (PEP 563),
binds nothing: a builtin it names, such as ``eval``, stays the builtin. Either way, its
lambdas and comprehensions introduce scopes of their own, which keep their bindings.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.semantic.scopes import BindingKind, Scope, ScopeTable, analyze_scopes
from coretrace_python.source import SourceManager

POSTPONED = "from __future__ import annotations\n\n"
PLUGINS = [engine.BUNDLED_PLUGINS]
# The comprehension never runs, and its annotation is a string: ``eval`` stays the builtin.
SHADOWING = POSTPONED + "def f(x: [(eval := i) for i in ()]):\n    pass\n\n\ndef run():\n    eval(input())\n"
EVAL_FINDINGS = {("code-injection", 8), ("dangerous-eval", 8)}


def analyze(text: str) -> ScopeTable:
    return analyze_scopes(build_hir(SourceManager().add_source("app.py", text)))


def child(scopes: ScopeTable, parent: Scope, name: str) -> Scope:
    (found,) = (scope for scope in scopes.children(parent.id) if scope.name == name)
    return found


def located(findings: Iterable[Finding]) -> set[tuple[str, int]]:
    return {(finding.rule_id, finding.span.start_line) for finding in findings}


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


def test_a_postponed_parameter_annotation_binds_nothing_where_it_stands() -> None:
    scopes = analyze(POSTPONED + "def f(x: [(found := i) for i in (1,)]):\n    pass\n")

    assert "found" not in scopes.module_scope.bindings
    assert child(scopes, scopes.module_scope, "<listcomp>").parent == scopes.module_scope.id


@pytest.mark.parametrize(
    "header",
    ["from .__future__ import annotations\n", "from __future__ import division\n", "import __future__\n"],
)
def test_only_the_future_statement_postpones_annotations(header: str) -> None:
    scopes = analyze(header + "def f(x: [(found := i) for i in (1,)]):\n    pass\n")

    assert "found" in scopes.module_scope.bindings


def test_assignment_expressions_after_a_postponed_annotation_still_bind() -> None:
    scopes = analyze(POSTPONED + "def f(x: (lambda: 1)):\n    pass\n\n\n[(found := i) for i in (1,)]\n")

    assert "found" in scopes.module_scope.bindings


def test_a_postponed_annotation_in_a_function_still_declares_there() -> None:
    scopes = analyze(POSTPONED + "def outer():\n    def inner(x: [(found := i) for i in (1,)]):\n        pass\n")

    assert "found" in child(scopes, scopes.module_scope, "outer").bindings
    assert "found" not in scopes.module_scope.bindings


def test_a_builtin_named_in_a_postponed_annotation_stays_the_builtin_in_a_file() -> None:
    findings = engine.check(SourceManager().add_source("app.py", SHADOWING), PLUGINS)

    assert located(findings) == EVAL_FINDINGS


def test_a_builtin_named_in_a_postponed_annotation_stays_the_builtin_in_a_project(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(SHADOWING, encoding="utf-8")

    assert located(engine.analyze_project(tmp_path, PLUGINS).findings) == EVAL_FINDINGS


def test_a_lambda_or_comprehension_in_a_variable_annotation_leaves_a_project_analysable(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "settings: (lambda: 1)\n\n\ndef run():\n    pending: [v for v in ()]\n    eval(input())\n", encoding="utf-8"
    )

    assert located(engine.analyze_project(tmp_path, PLUGINS).findings) == {("code-injection", 6), ("dangerous-eval", 6)}


def test_a_module_variable_annotation_binds_where_it_stands() -> None:
    scopes = analyze("settings: [(found := i) for i in (1,)]\n")

    assert "found" in scopes.module_scope.bindings
    assert child(scopes, scopes.module_scope, "<listcomp>").parent == scopes.module_scope.id


@pytest.mark.parametrize("header", ["", POSTPONED])
def test_a_local_variable_annotation_declares_in_its_function(header: str) -> None:
    scopes = analyze(header + "def run():\n    pending: [(found := i) for i in (1,)]\n")
    run = child(scopes, scopes.module_scope, "run")

    assert "found" in run.bindings
    assert child(scopes, run, "<listcomp>").parent == run.id


def test_a_postponed_module_variable_annotation_binds_nothing() -> None:
    scopes = analyze(POSTPONED + "settings: [(found := i) for i in (1,)]\n")

    assert "found" not in scopes.module_scope.bindings
