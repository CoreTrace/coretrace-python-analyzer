"""Acceptance tests for imports and canonical symbol resolution."""

from __future__ import annotations

import pytest

from coretrace_python.cli import main
from coretrace_python.cli import main as main_cli


def emit_ir(source_text: str, tmp_path, capsys) -> tuple[int, str, str]:
    source = tmp_path / "symbols.py"
    source.write_text(source_text, encoding="utf-8")

    exit_code = main(["--emit-ir", str(source)])
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


@pytest.mark.parametrize(
    "import_statement, call_expression",
    [
        ("import os", "os.system(command)"),
        ("import os as operating_system", "operating_system.system(command)"),
        ("from os import system", "system(command)"),
        ("from os import system as run", "run(command)"),
    ],
    ids=["module", "module-alias", "from-import", "from-import-alias"],
)
def test_os_system_import_styles_resolve_to_the_same_symbol(
    import_statement: str,
    call_expression: str,
    tmp_path,
    capsys,
) -> None:
    exit_code, output, error = emit_ir(
        f"{import_statement}\n\n"
        "def execute(command):\n"
        f"    {call_expression}\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "symbol @python.os.system" in output
    assert "global 'os'" not in output
    assert "global 'operating_system'" not in output
    assert "global 'system'" not in output
    assert "global 'run'" not in output


def test_nested_module_symbol_is_canonicalized(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "import subprocess as sp\n\n"
        "def execute(command):\n"
        "    sp.run(command)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "symbol @python.subprocess.run" in output
    assert "global 'sp'" not in output


def test_import_bindings_are_available_to_every_function(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "from os import system\n\n"
        "def first(command):\n"
        "    system(command)\n\n"
        "def second(command):\n"
        "    system(command)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert output.count("symbol @python.os.system") == 2
    assert "func @first(%0)" in output
    assert "func @second(%0)" in output


def test_unknown_name_remains_a_global(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "def greet(name):\n"
        "    undefined_helper(name)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "%1 = global 'undefined_helper'" in output
    assert "symbol @" not in output


def test_local_assignment_shadows_an_import_binding(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "from os import system as run\n\n"
        "def execute(callback, command):\n"
        "    run = callback\n"
        "    run(command)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert 'store_local "run", %0' in output
    assert 'load_local "run"' in output
    assert "symbol @python.os.system" not in output


def test_wildcard_import_leaves_names_unresolved(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "from os import *\n\n"
        "def execute(command):\n"
        "    system(command)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "%1 = global 'system'" in output
    assert "symbol @" not in output


# --------------------------------------------------------------------------- next milestone
# Lowering must consume the Phase 2 ScopeTable instead of tracking locals itself
# (docs/architecture.md §4.1 and boundary "PyIR lowering consumes semantic results").
# Expected to remain red until lowering is routed through scope analysis.


def test_read_before_assignment_is_local_not_an_import(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "from os import system as run\n\n"
        "def execute(callback, command):\n"
        "    run(command)\n"
        "    run = callback\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "symbol @python.os.system" not in output
    assert 'load_local "run"' in output
    assert 'store_local "run", %0' in output


def test_global_declaration_is_not_a_local(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "import os\n\n"
        "def execute(command):\n"
        "    global os\n"
        "    os.system(command)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "symbol @python.os.system" in output
    assert 'load_local "os"' not in output


# --------------------------------------------------------------------------- symbol analysis
# Lowering resolves names through the Phase 2 SymbolTable (docs/architecture.md §4.2,
# §4.3): builtins, function-level and relative imports become canonical symbols.
# Expected to remain red until symbol analysis lands.


def test_builtins_are_canonical_symbols(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "def greet(name):\n"
        "    print(name)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "%1 = symbol @python.builtins.print" in output
    assert "global 'print'" not in output


def test_function_level_import_resolves_to_a_symbol(tmp_path, capsys) -> None:
    exit_code, output, error = emit_ir(
        "def execute(command):\n"
        "    import os\n"
        "    os.system(command)\n",
        tmp_path,
        capsys,
    )

    assert exit_code == 0, error
    assert "symbol @python.os.system" in output


def test_relative_import_resolves_inside_a_package(tmp_path, capsys) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helpers.py").write_text("def run(command):\n    return command\n", encoding="utf-8")
    main = package / "main.py"
    main.write_text(
        "from .helpers import run\n\n"
        "def execute(command):\n"
        "    run(command)\n",
        encoding="utf-8",
    )

    exit_code = main_cli(["--emit-ir", str(main)])
    captured = capsys.readouterr()

    assert exit_code == 0, captured.err
    assert "symbol @python.pkg.helpers.run" in captured.out
