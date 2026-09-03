"""Acceptance tests for lexical scope analysis (``docs/architecture.md`` §4.1).

This module describes the public behavior of the Phase 2 ``ScopeTable``. It is
expected to remain red until ``coretrace_python.semantic.scopes`` exists.

Contract under test:

- ``analyze_scopes(module: hir.Module) -> ScopeTable`` is a pure function over PyHIR.
- ``ScopeTable`` exposes ``module_scope``, ``scope(id)``, ``children(id)`` and
  ``resolve(id, name)``.
- ``Scope`` and ``Binding`` are immutable and keyed by a stable ``ScopeId``.
- Resolution follows Python rules: an assignment anywhere in a function makes the name
  local for the whole function, class bodies are skipped by nested functions, and
  comprehensions have their own scope.
"""

from __future__ import annotations

import dataclasses

import pytest

from coretrace_python.source import SourceManager

try:
    from coretrace_python.frontend import build_hir
    from coretrace_python.semantic.scopes import (
        BindingKind,
        ResolutionKind,
        Scope,
        ScopeError,
        ScopeKind,
        ScopeTable,
        analyze_scopes,
    )
except ImportError as error:  # pragma: no cover - red until the semantic layer lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_semantic_layer() -> None:
    if MISSING is not None:
        pytest.fail(f"semantic scope analysis is not implemented yet: {MISSING}")


def analyze(source_text: str) -> ScopeTable:
    source = SourceManager().add_source("scopes.py", source_text)
    return analyze_scopes(build_hir(source))


def child(analysis: ScopeTable, parent: Scope, name: str) -> Scope:
    matches = [scope for scope in analysis.children(parent.id) if scope.name == name]
    assert len(matches) == 1, f"expected one child scope named {name!r}, found {matches}"
    return matches[0]


# --------------------------------------------------------------------------- module scope


def test_module_scope_is_the_root() -> None:
    analysis = analyze("import os\nvalue = 1\n")
    module = analysis.module_scope

    assert module.kind is ScopeKind.MODULE
    assert module.parent is None
    assert module.bindings["os"].kind is BindingKind.IMPORT
    assert module.bindings["value"].kind is BindingKind.LOCAL
    assert analysis.scope(module.id) is module


def test_definitions_bind_their_name_in_the_enclosing_scope() -> None:
    analysis = analyze("def foo():\n    pass\n\nclass Bar:\n    pass\n")
    module = analysis.module_scope

    assert module.bindings["foo"].kind is BindingKind.FUNCTION
    assert module.bindings["Bar"].kind is BindingKind.CLASS
    assert child(analysis, module, "foo").kind is ScopeKind.FUNCTION
    assert child(analysis, module, "Bar").kind is ScopeKind.CLASS


def test_bindings_record_their_first_binding_site() -> None:
    analysis = analyze("x = 1\nx = 2\n")
    binding = analysis.module_scope.bindings["x"]

    assert binding.span.start_line == 1
    assert binding.span.start_column == 1


# --------------------------------------------------------------------------- functions


def test_same_name_in_module_and_function_are_distinct_bindings() -> None:
    # The example from §4.1: the engine must distinguish between the two ``x`` symbols.
    analysis = analyze("x = 1\n\ndef foo():\n    x = 2\n    return x\n")
    module = analysis.module_scope
    foo = child(analysis, module, "foo")

    assert module.bindings["x"] != foo.bindings["x"]
    assert analysis.resolve(foo.id, "x").kind is ResolutionKind.LOCAL
    assert analysis.resolve(foo.id, "x").scope == foo.id
    assert analysis.resolve(module.id, "x").kind is ResolutionKind.GLOBAL
    assert analysis.resolve(module.id, "x").scope == module.id


def test_parameters_are_local_bindings() -> None:
    analysis = analyze("def add(a, b):\n    return a + b\n")
    add = child(analysis, analysis.module_scope, "add")

    assert add.bindings["a"].kind is BindingKind.PARAMETER
    assert add.bindings["b"].kind is BindingKind.PARAMETER
    assert analysis.resolve(add.id, "a").kind is ResolutionKind.LOCAL


def test_assignment_anywhere_makes_the_name_local_for_the_whole_function() -> None:
    # Python decides locality per function, not per statement order. Reading ``run``
    # before assigning it must not resolve to the module-level import.
    analysis = analyze(
        "from os import system as run\n\n"
        "def execute(callback, command):\n"
        "    run(command)\n"
        "    run = callback\n"
    )
    execute = child(analysis, analysis.module_scope, "execute")

    assert execute.bindings["run"].kind is BindingKind.LOCAL
    assert analysis.resolve(execute.id, "run").kind is ResolutionKind.LOCAL


def test_unassigned_name_in_function_resolves_to_module_binding() -> None:
    analysis = analyze("import os\n\ndef execute(command):\n    os.system(command)\n")
    execute = child(analysis, analysis.module_scope, "execute")

    assert "os" not in execute.bindings
    resolution = analysis.resolve(execute.id, "os")
    assert resolution.kind is ResolutionKind.GLOBAL
    assert resolution.scope == analysis.module_scope.id


def test_name_bound_nowhere_is_unbound() -> None:
    analysis = analyze("def greet(name):\n    print(name)\n")
    greet = child(analysis, analysis.module_scope, "greet")

    resolution = analysis.resolve(greet.id, "print")
    assert resolution.kind is ResolutionKind.UNBOUND
    assert resolution.scope is None
    assert analysis.resolve(analysis.module_scope.id, "print").kind is ResolutionKind.UNBOUND


def test_function_level_import_binds_a_local_name() -> None:
    analysis = analyze("def execute(command):\n    import os\n    os.system(command)\n")
    execute = child(analysis, analysis.module_scope, "execute")

    assert execute.bindings["os"].kind is BindingKind.IMPORT
    assert analysis.resolve(execute.id, "os").kind is ResolutionKind.LOCAL


# --------------------------------------------------------------------------- closures


def test_nested_function_reads_enclosing_local_as_free_variable() -> None:
    analysis = analyze(
        "def outer():\n"
        "    secret = 1\n"
        "    def inner():\n"
        "        return secret\n"
        "    return inner\n"
    )
    outer = child(analysis, analysis.module_scope, "outer")
    inner = child(analysis, outer, "inner")

    assert inner.parent == outer.id
    assert "secret" not in inner.bindings
    resolution = analysis.resolve(inner.id, "secret")
    assert resolution.kind is ResolutionKind.FREE
    assert resolution.scope == outer.id


def test_nested_assignment_shadows_instead_of_capturing() -> None:
    analysis = analyze(
        "def outer():\n"
        "    value = 1\n"
        "    def inner():\n"
        "        value = 2\n"
        "        return value\n"
        "    return inner\n"
    )
    outer = child(analysis, analysis.module_scope, "outer")
    inner = child(analysis, outer, "inner")

    assert inner.bindings["value"].kind is BindingKind.LOCAL
    assert analysis.resolve(inner.id, "value").scope == inner.id
    assert analysis.resolve(outer.id, "value").scope == outer.id


def test_nonlocal_declaration_rebinds_the_enclosing_variable() -> None:
    analysis = analyze(
        "def counter():\n"
        "    count = 0\n"
        "    def increment():\n"
        "        nonlocal count\n"
        "        count = count + 1\n"
        "    return increment\n"
    )
    counter = child(analysis, analysis.module_scope, "counter")
    increment = child(analysis, counter, "increment")

    assert increment.bindings["count"].kind is BindingKind.NONLOCAL
    resolution = analysis.resolve(increment.id, "count")
    assert resolution.kind is ResolutionKind.FREE
    assert resolution.scope == counter.id


def test_global_declaration_binds_in_the_module_scope() -> None:
    analysis = analyze("def configure():\n    global total\n    total = 1\n")
    module = analysis.module_scope
    configure = child(analysis, module, "configure")

    assert configure.bindings["total"].kind is BindingKind.GLOBAL
    assert module.bindings["total"].kind is BindingKind.LOCAL
    resolution = analysis.resolve(configure.id, "total")
    assert resolution.kind is ResolutionKind.GLOBAL
    assert resolution.scope == module.id


def test_free_variable_resolves_through_several_levels() -> None:
    analysis = analyze(
        "def a():\n"
        "    x = 1\n"
        "    def b():\n"
        "        def c():\n"
        "            return x\n"
        "        return c\n"
        "    return b\n"
    )
    a = child(analysis, analysis.module_scope, "a")
    b = child(analysis, a, "b")
    c = child(analysis, b, "c")

    resolution = analysis.resolve(c.id, "x")
    assert resolution.kind is ResolutionKind.FREE
    assert resolution.scope == a.id


# --------------------------------------------------------------------------- classes


def test_class_body_names_are_local_to_the_class_scope() -> None:
    analysis = analyze("class Config:\n    debug = True\n")
    config = child(analysis, analysis.module_scope, "Config")

    assert config.kind is ScopeKind.CLASS
    assert config.bindings["debug"].kind is BindingKind.LOCAL
    assert analysis.resolve(config.id, "debug").kind is ResolutionKind.LOCAL


def test_methods_skip_the_class_scope_when_resolving_names() -> None:
    analysis = analyze(
        "x = 1\n\n"
        "class Holder:\n"
        "    x = 2\n"
        "    def read(self):\n"
        "        return x\n"
    )
    module = analysis.module_scope
    holder = child(analysis, module, "Holder")
    read = child(analysis, holder, "read")

    assert read.parent == holder.id
    assert holder.bindings["read"].kind is BindingKind.FUNCTION
    resolution = analysis.resolve(read.id, "x")
    assert resolution.kind is ResolutionKind.GLOBAL
    assert resolution.scope == module.id


def test_class_body_reads_enclosing_function_locals() -> None:
    analysis = analyze(
        "def factory():\n"
        "    base = 1\n"
        "    class Product:\n"
        "        value = base\n"
        "    return Product\n"
    )
    factory = child(analysis, analysis.module_scope, "factory")
    product = child(analysis, factory, "Product")

    resolution = analysis.resolve(product.id, "base")
    assert resolution.kind is ResolutionKind.FREE
    assert resolution.scope == factory.id


# --------------------------------------------------------------------------- comprehensions


def test_comprehension_has_its_own_scope() -> None:
    analysis = analyze(
        "def squares(items, threshold):\n"
        "    return [y * y for y in items if y > threshold]\n"
    )
    squares = child(analysis, analysis.module_scope, "squares")
    comprehension = child(analysis, squares, "<listcomp>")

    assert comprehension.kind is ScopeKind.COMPREHENSION
    assert comprehension.parent == squares.id
    assert comprehension.bindings["y"].kind is BindingKind.LOCAL
    assert "y" not in squares.bindings
    assert analysis.resolve(comprehension.id, "y").kind is ResolutionKind.LOCAL
    threshold = analysis.resolve(comprehension.id, "threshold")
    assert threshold.kind is ResolutionKind.FREE
    assert threshold.scope == squares.id


# --------------------------------------------------------------------------- errors


@pytest.mark.parametrize(
    "source_text, location",
    [
        (
            "def outer():\n    def inner():\n        nonlocal count\n        count = 1\n",
            "scopes.py:3:9",
        ),
        ("nonlocal value\n", "scopes.py:1:1"),
    ],
    ids=["no-enclosing-binding", "module-level"],
)
def test_invalid_nonlocal_is_a_source_located_error(source_text: str, location: str) -> None:
    with pytest.raises(ScopeError, match=rf"{location}: .*nonlocal"):
        analyze(source_text)


# --------------------------------------------------------------------------- result shape


def test_results_are_immutable() -> None:
    analysis = analyze("x = 1\n")
    module = analysis.module_scope

    with pytest.raises(dataclasses.FrozenInstanceError):
        module.name = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        module.bindings["y"] = module.bindings["x"]  # type: ignore[index]


def test_results_are_deterministic_across_runs() -> None:
    source_text = "x = 1\n\ndef foo(a):\n    def bar():\n        return a\n    return bar\n"
    first = analyze(source_text)
    second = analyze(source_text)

    assert first.module_scope == second.module_scope
    assert first.children(first.module_scope.id) == second.children(second.module_scope.id)
    foo = child(first, first.module_scope, "foo")
    assert first.children(foo.id) == second.children(child(second, second.module_scope, "foo").id)


def test_children_are_listed_in_source_order() -> None:
    analysis = analyze("def b():\n    pass\n\ndef a():\n    pass\n\nclass C:\n    pass\n")
    names = [scope.name for scope in analysis.children(analysis.module_scope.id)]

    assert names == ["b", "a", "C"]


def test_unknown_scope_id_is_rejected() -> None:
    analysis = analyze("x = 1\n")
    other = analyze("def foo():\n    pass\n")
    foreign = child(other, other.module_scope, "foo").id

    with pytest.raises(KeyError):
        analysis.scope(foreign)
