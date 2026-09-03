"""Acceptance tests for canonical symbols (``docs/architecture.md`` §4.3).

``SymbolId`` is a namespace-qualified dotted identity. ``SymbolAnalysis`` resolves any
name in any scope to such an identity through scope rules, imports and builtins, so
security rules never depend on the textual name visible in the file.

The ``analyze_symbols`` tests are expected to remain red until symbol analysis lands.
"""

from __future__ import annotations

import pytest

from coretrace_python.frontend import build_hir
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeId, analyze_scopes
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

try:
    from coretrace_python.semantic.imports import analyze_imports
    from coretrace_python.semantic.symbols import SymbolAnalysis, analyze_symbols
except ImportError as error:  # pragma: no cover - red until symbol analysis lands
    MISSING = error
else:
    MISSING = None


# --------------------------------------------------------------------------- SymbolId


def test_symbol_id_adds_the_python_namespace() -> None:
    symbol = SymbolId.from_python_path("os.system")
    assert symbol.canonical_name == "python.os.system"


def test_symbol_id_does_not_duplicate_the_python_namespace() -> None:
    symbol = SymbolId.from_python_path("python.os.system")
    assert symbol.canonical_name == "python.os.system"


def test_symbol_attribute_creates_a_child_identity() -> None:
    module = SymbolId.from_python_path("os")
    assert module.attribute("system") == SymbolId("python.os.system")


@pytest.mark.parametrize("path", ["", ".os"])
def test_invalid_symbol_paths_are_rejected(path: str) -> None:
    with pytest.raises(ValueError):
        SymbolId.from_python_path(path)


@pytest.mark.parametrize(
    "name", ["flask.request.args", "django.http.HttpRequest.GET", "python.builtins.eval"]
)
def test_symbol_id_accepts_any_namespace(name: str) -> None:
    assert SymbolId(name).canonical_name == name


@pytest.mark.parametrize("name", ["", "os", ".os", "os.", "a..b", "python."])
def test_symbol_id_requires_a_namespace_and_non_empty_components(name: str) -> None:
    with pytest.raises(ValueError):
        SymbolId(name)


# --------------------------------------------------------------------------- SymbolAnalysis


@pytest.fixture
def symbols() -> None:
    if MISSING is not None:
        pytest.fail(f"symbol analysis is not implemented yet: {MISSING}")


def analyze(source_text: str) -> tuple[ScopeAnalysis, SymbolAnalysis]:
    source = SourceManager().add_source("symbols.py", source_text)
    module = build_hir(source)
    scopes = analyze_scopes(module)
    return scopes, analyze_symbols(scopes, analyze_imports(module, scopes))


def scope_named(scopes: ScopeAnalysis, name: str) -> ScopeId:
    return next(s for s in scopes.children(scopes.module_scope.id) if s.name == name).id


@pytest.mark.usefixtures("symbols")
def test_module_import_resolves_from_a_function() -> None:
    scopes, symbols = analyze("import os\n\ndef execute(command):\n    os.system(command)\n")
    assert symbols.resolve(scope_named(scopes, "execute"), "os") == SymbolId("python.os")
    assert symbols.resolve(scopes.module_scope.id, "os") == SymbolId("python.os")


@pytest.mark.usefixtures("symbols")
def test_function_level_import_resolves_only_inside_the_function() -> None:
    scopes, symbols = analyze("def execute(command):\n    import os\n    os.system(command)\n")
    assert symbols.resolve(scope_named(scopes, "execute"), "os") == SymbolId("python.os")
    assert symbols.resolve(scopes.module_scope.id, "os") is None


@pytest.mark.usefixtures("symbols")
def test_import_captured_by_a_nested_function_resolves() -> None:
    scopes, symbols = analyze(
        "def outer():\n"
        "    from os import system as run\n"
        "    def inner(command):\n"
        "        return run(command)\n"
        "    return inner\n"
    )
    outer = scope_named(scopes, "outer")
    inner = next(s for s in scopes.children(outer) if s.name == "inner").id
    assert symbols.resolve(inner, "run") == SymbolId("python.os.system")


@pytest.mark.usefixtures("symbols")
def test_local_assignment_shadows_an_import() -> None:
    scopes, symbols = analyze(
        "from os import system as run\n\n"
        "def execute(callback, command):\n"
        "    run(command)\n"
        "    run = callback\n"
    )
    assert symbols.resolve(scope_named(scopes, "execute"), "run") is None


@pytest.mark.usefixtures("symbols")
def test_global_declaration_reaches_the_module_import() -> None:
    scopes, symbols = analyze("import os\n\ndef execute(command):\n    global os\n    os.system(command)\n")
    assert symbols.resolve(scope_named(scopes, "execute"), "os") == SymbolId("python.os")


@pytest.mark.usefixtures("symbols")
def test_builtins_resolve_to_the_builtins_namespace() -> None:
    scopes, symbols = analyze("def greet(name):\n    print(name)\n    eval(name)\n")
    greet = scope_named(scopes, "greet")
    assert symbols.resolve(greet, "print") == SymbolId("python.builtins.print")
    assert symbols.resolve(greet, "eval") == SymbolId("python.builtins.eval")
    assert symbols.resolve(scopes.module_scope.id, "open") == SymbolId("python.builtins.open")


@pytest.mark.usefixtures("symbols")
def test_rebound_builtin_is_not_a_builtin() -> None:
    scopes, symbols = analyze("print = 1\n\ndef greet(name):\n    print(name)\n")
    assert symbols.resolve(scope_named(scopes, "greet"), "print") is None


@pytest.mark.usefixtures("symbols")
def test_unknown_and_wildcard_provided_names_are_unresolved() -> None:
    scopes, symbols = analyze("from os import *\n\ndef execute(command):\n    system(command)\n    helper(command)\n")
    execute = scope_named(scopes, "execute")
    assert symbols.resolve(execute, "system") is None
    assert symbols.resolve(execute, "helper") is None
