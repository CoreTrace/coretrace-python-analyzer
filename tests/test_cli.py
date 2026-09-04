"""CLI contract: ``--emit-ir`` prints PyIR, ``--check`` runs plugins and reports findings.

Exit codes: 0 clean, 1 findings reported, 2 usage or analysis error.

The ``--check`` tests are expected to remain red until the engine wires plugins and
reporters into the CLI (docs/architecture.md §28).
"""

from __future__ import annotations

import json
from pathlib import Path

from coretrace_python.cli import main

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def write(tmp_path: Path, text: str, name: str = "target.py") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_cli_requires_an_action(tmp_path, capsys) -> None:
    source = write(tmp_path, "")
    assert main([str(source)]) == 2
    assert "no action selected" in capsys.readouterr().err


def test_analysis_errors_exit_with_two(tmp_path, capsys) -> None:
    source = write(tmp_path, "def broken(:\n")
    assert main(["--emit-ir", str(source)]) == 2
    assert "error:" in capsys.readouterr().err


def test_check_reports_findings_from_loaded_plugins(tmp_path, capsys) -> None:
    source = write(tmp_path, "def run(code):\n    eval(code)\n")

    exit_code = main(["--check", str(source), "--plugins", str(PLUGINS)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == (
        f"{source}:2:5: high dangerous-eval: call to python.builtins.eval executes"
        " dynamically built code [run]\n"
        "1 finding\n"
        "coverage: 1/1 files, 1/1 functions\n"
    )


def test_check_is_clean_when_nothing_is_found(tmp_path, capsys) -> None:
    source = write(tmp_path, "def run(code):\n    return code\n")

    assert main(["--check", str(source), "--plugins", str(PLUGINS)]) == 0
    assert capsys.readouterr().out == "no findings\ncoverage: 1/1 files, 1/1 functions\n"


def test_check_without_plugins_finds_nothing(tmp_path, capsys) -> None:
    source = write(tmp_path, "def run(code):\n    eval(code)\n")

    assert main(["--check", str(source), "--no-bundled-plugins"]) == 0
    assert capsys.readouterr().out == "no findings\ncoverage: 1/1 files, 1/1 functions\n"


def test_check_json_format(tmp_path, capsys) -> None:
    source = write(tmp_path, "def run(code):\n    eval(code)\n")

    exit_code = main(["--check", str(source), "--plugins", str(PLUGINS), "--format", "json"])
    document = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert document["tool"]["name"] == "coretrace-python-analyzer"
    assert [f["rule_id"] for f in document["findings"]] == ["dangerous-eval"]
    assert document["findings"][0]["location"]["path"] == str(source)


def test_check_sarif_format(tmp_path, capsys) -> None:
    source = write(tmp_path, "def run(code):\n    eval(code)\n")

    exit_code = main(["--check", str(source), "--plugins", str(PLUGINS), "--format", "sarif"])
    document = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "dangerous-eval"


def test_check_reports_analysis_errors(tmp_path, capsys) -> None:
    source = write(tmp_path, "def broken(:\n")

    assert main(["--check", str(source), "--plugins", str(PLUGINS)]) == 2
    assert "error:" in capsys.readouterr().err


def test_check_reports_bad_plugin_directories(tmp_path, capsys) -> None:
    source = write(tmp_path, "def run():\n    pass\n")
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "plugin.toml").write_text("name = 'x'\n", encoding="utf-8")

    assert main(["--check", str(source), "--plugins", str(broken)]) == 2
    assert "plugin.toml" in capsys.readouterr().err


def test_format_requires_check(tmp_path, capsys) -> None:
    source = write(tmp_path, "")
    assert main(["--emit-ir", "--format", "json", str(source)]) == 2
    assert "--format" in capsys.readouterr().err
