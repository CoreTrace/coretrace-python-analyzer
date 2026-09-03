"""Acceptance tests for import analysis (``docs/architecture.md`` §4.2).

Every import binding maps a local name to a canonical, alias-independent identity.
Imports are collected per scope, relative imports resolve against the module's dotted
name, and wildcard imports are recorded instead of aborting the analysis.

Expected to remain red until ``analyze_imports`` replaces ``collect_imports``.
"""

from __future__ import annotations

import pytest

from coretrace_python.frontend import build_hir
from coretrace_python.semantic.scopes import Scope, ScopeAnalysis, analyze_scopes
from coretrace_python.source import SourceManager

try:
    from coretrace_python.semantic.imports import (
        ImportAnalysis,
        ImportResolutionError,
        analyze_imports,
    )
    from coretrace_python.semantic.symbols import SymbolId
except ImportError as error:  # pragma: no cover - red until import analysis lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_import_analysis() -> None:
    if MISSING is not None:
        pytest.fail(f"import analysis is not implemented yet: {MISSING}")


def analyze(source_text: str, module_name: str = "imports") -> tuple[ScopeAnalysis, ImportAnalysis]:
    source = SourceManager().add_source("imports.py", source_text, module_name=module_name)
    module = build_hir(source)
    scopes = analyze_scopes(module)
    return scopes, analyze_imports(module, scopes)


def function_scope(scopes: ScopeAnalysis, name: str) -> Scope:
    return next(s for s in scopes.children(scopes.module_scope.id) if s.name == name)


def test_collects_plain_and_aliased_imports() -> None:
    scopes, imports = analyze("import os\nimport subprocess as sp\n")
    bindings = imports.bindings(scopes.module_scope.id)

    assert bindings["os"] == SymbolId("python.os")
    assert bindings["sp"] == SymbolId("python.subprocess")


def test_plain_dotted_import_binds_its_top_level_package() -> None:
    scopes, imports = analyze("import xml.etree.ElementTree\n")
    assert imports.bindings(scopes.module_scope.id)["xml"] == SymbolId("python.xml")


def test_aliased_dotted_import_binds_the_full_path() -> None:
    scopes, imports = analyze("import xml.etree.ElementTree as ET\n")
    bindings = imports.bindings(scopes.module_scope.id)
    assert bindings["ET"] == SymbolId("python.xml.etree.ElementTree")


def test_collects_from_imports() -> None:
    scopes, imports = analyze("from os import system as run, path\n")
    bindings = imports.bindings(scopes.module_scope.id)

    assert bindings["run"] == SymbolId("python.os.system")
    assert bindings["path"] == SymbolId("python.os.path")


def test_function_level_imports_bind_in_the_function_scope() -> None:
    scopes, imports = analyze("def execute(command):\n    import os\n    os.system(command)\n")
    execute = function_scope(scopes, "execute")

    assert imports.bindings(execute.id)["os"] == SymbolId("python.os")
    assert "os" not in imports.bindings(scopes.module_scope.id)


@pytest.mark.parametrize(
    "statement, name, expected",
    [
        ("from . import utils", "utils", "python.app.services.utils"),
        ("from .db import query as q", "q", "python.app.services.db.query"),
        ("from ..models import User", "User", "python.app.models.User"),
        ("from .. import config", "config", "python.app.config"),
    ],
    ids=["sibling-module", "sibling-attribute", "parent-module", "parent-package"],
)
def test_relative_imports_resolve_against_the_module_name(
    statement: str, name: str, expected: str
) -> None:
    scopes, imports = analyze(f"{statement}\n", module_name="app.services.db")
    assert imports.bindings(scopes.module_scope.id)[name] == SymbolId(expected)


@pytest.mark.parametrize(
    "source_text, module_name",
    [("from ... import x\n", "app.services.db"), ("from . import x\n", "script")],
    ids=["too-many-levels", "top-level-script"],
)
def test_relative_import_beyond_the_top_level_package_is_an_error(
    source_text: str, module_name: str
) -> None:
    with pytest.raises(ImportResolutionError, match=r"imports.py:1:1: .*beyond top-level package"):
        analyze(source_text, module_name=module_name)


def test_wildcard_imports_are_recorded_without_bindings() -> None:
    scopes, imports = analyze("from os import *\n")
    module = scopes.module_scope.id

    assert imports.bindings(module) == {}
    assert imports.wildcards(module) == (SymbolId("python.os"),)


def test_bindings_are_immutable() -> None:
    scopes, imports = analyze("import os\n")
    with pytest.raises(TypeError):
        imports.bindings(scopes.module_scope.id)["sys"] = SymbolId("python.sys")  # type: ignore[index]
