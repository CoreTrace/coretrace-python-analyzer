"""Acceptance tests for the last PyIR leftovers (``docs/architecture.md`` §6, §39 rule 3;
roadmap issue #13).

An import inside a function runs where it stands, so PyIR shows it: an ``Import``
effect instruction names the module as written, the canonical symbol bound and the local
name. Uses of that name keep resolving to ``Symbol`` values, as before. Module-level
imports are applied by the semantic analyses and lower to nothing, since ``ModuleIR``
holds functions only. ``PYIR_SCHEMA_VERSION`` versions the instruction set and is part of
the persistent cache key.

Expected to remain red until ``ir.model.Import`` and ``PYIR_SCHEMA_VERSION`` exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.frontend import build_hir
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.model import FunctionIR, Instruction, Symbol
from coretrace_python.source import SourceManager

try:
    from coretrace_python.ir import PYIR_SCHEMA_VERSION
    from coretrace_python.ir.model import Import
except ImportError as error:  # pragma: no cover - red until the instruction lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_imports() -> None:
    if MISSING is not None:
        pytest.fail(f"PyIR imports are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def lower(text: str, *, ssa: bool = False, name: str = "ir.py") -> FunctionIR:
    module = lower_module(build_hir(SourceManager().add_source(name, text)), ssa=ssa)
    return module.functions[0]


def instructions(function: FunctionIR, kind: type[Instruction]) -> list[Instruction]:
    return [i for block in function.blocks for i in block.instructions if isinstance(i, kind)]


# --------------------------------------------------------------------------- instruction


def test_local_imports_lower_to_import_instructions() -> None:
    function = lower("def f():\n    import os\n    import os.path as p\n    return os.system, p.join\n")

    imports = instructions(function, Import)

    assert [(i.module, str(i.symbol_id), i.name) for i in imports] == [
        ("os", "python.os", "os"),
        ("os.path", "python.os.path", "p"),
    ]
    assert all(i.result is None and i.operands() == () for i in imports)
    assert imports[0].location.start_line == 2
    assert [str(s.symbol_id) for s in instructions(function, Symbol)] == ["python.os.system", "python.os.path.join"]


def test_from_imports_and_relative_imports_are_faithful(tmp_path: Path) -> None:
    function = lower("def f():\n    from subprocess import run as launch\n    return launch\n")
    (launch,) = instructions(function, Import)
    assert (launch.module, str(launch.symbol_id), launch.name) == ("subprocess", "python.subprocess.run", "launch")

    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helpers.py").write_text("def go():\n    pass\n", encoding="utf-8")
    (package / "main.py").write_text("def f():\n    from . import helpers\n    from .helpers import go\n    return go\n", encoding="utf-8")
    module = lower_module(build_hir(SourceManager().load_file(package / "main.py")))
    relative = instructions(module.functions[0], Import)

    assert [(i.module, str(i.symbol_id), i.name) for i in relative] == [
        (".", "python.pkg.helpers", "helpers"),
        (".helpers", "python.pkg.helpers.go", "go"),
    ]


def test_imports_come_before_the_uses_and_survive_ssa() -> None:
    function = lower("def f(x):\n    if x:\n        import os\n        os.system(x)\n", ssa=True)

    (block,) = [b for b in function.blocks if instructions_of(b, Import)]
    kinds = [type(i).__name__ for i in block.instructions]

    assert kinds.index("Import") < kinds.index("Symbol")


def instructions_of(block, kind):  # type: ignore[no-untyped-def]
    return [i for i in block.instructions if isinstance(i, kind)]


def test_module_level_imports_lower_to_nothing() -> None:
    function = lower("import os\n\ndef f():\n    return os.system\n")
    assert instructions(function, Import) == []


def test_emit_ir_prints_imports(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "late.py"
    source.write_text("def f():\n    import json as j\n    return j\n", encoding="utf-8")

    assert main(["--emit-ir", str(source)]) == 0
    assert capsys.readouterr().out == (
        "func @f() {\n"
        "entry:\n"
        '    import "json" as "j" @python.json\n'
        "    %0 = symbol @python.json\n"
        "    return %0\n"
        "}\n"
    )


def test_analyses_see_through_local_imports() -> None:
    findings = engine.check(
        SourceManager().add_source("late.py", "def f():\n    import os\n    os.system(input())\n"), [PLUGINS]
    )
    assert [(f.rule_id, f.span.start_line) for f in findings] == [("command-injection", 3)]


# --------------------------------------------------------------------------- schema version


def test_pyir_schema_version_is_exported_and_keys_the_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from coretrace_python.ir import model

    assert PYIR_SCHEMA_VERSION == model.PYIR_SCHEMA_VERSION >= 1
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    before = engine.analyze_project(tmp_path).keys["app"]

    monkeypatch.setattr(engine, "PYIR_SCHEMA_VERSION", PYIR_SCHEMA_VERSION + 1)

    assert engine.analyze_project(tmp_path).keys["app"] != before
