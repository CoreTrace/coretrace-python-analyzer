from __future__ import annotations

import pytest

from coretrace_python.frontend import build_hir
from coretrace_python.semantic.imports import (
    ImportBindings,
    ImportResolutionError,
    collect_imports,
)
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager


def bindings_for(source: str) -> ImportBindings:
    source_file = SourceManager().add_source("imports.py", source)
    return collect_imports(build_hir(source_file))


def test_collects_plain_and_aliased_imports() -> None:
    bindings = bindings_for("import os\nimport subprocess as sp\n")
    assert bindings["os"] == SymbolId("python.os")
    assert bindings["sp"] == SymbolId("python.subprocess")


def test_plain_dotted_import_binds_its_top_level_package() -> None:
    bindings = bindings_for("import xml.etree.ElementTree\n")
    assert bindings["xml"] == SymbolId("python.xml")


def test_collects_from_imports() -> None:
    bindings = bindings_for("from os import system as run\n")
    assert bindings["run"] == SymbolId("python.os.system")


def test_wildcard_import_is_rejected_with_location() -> None:
    with pytest.raises(
        ImportResolutionError,
        match=r"imports.py:1:1: wildcard imports are not supported",
    ):
        bindings_for("from os import *\n")
