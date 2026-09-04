"""Acceptance tests for two remaining audit recommendations: secrets in configuration
files and a coverage metric that tells "nothing found" from "nothing analysed".

- ``config-secrets`` is a project plugin walking ``.env``, YAML, TOML, JSON, INI and
  properties files under the root, decoded by their byte order mark, and judging each
  key-value pair with the same provider patterns, credential names and entropy rule as
  the Python literal detector; virtual environments and tooling directories are skipped.
- ``Coverage`` records, per file, whether it was analysed or why not, and how many of
  its functions were; the text and JSON reporters print it when a report carries one.

Expected to remain red until ``findings.coverage``, ``ProjectContext.root``,
``engine.analyze_file`` and the ``config-secrets`` plugin exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.reporters import Report, render_json, render_text
from coretrace_python.source import SourceId, SourceManager, SourceSpan

try:
    from coretrace_python.findings.coverage import Coverage, FileCoverage
    from coretrace_python.plugins import ProjectContext
    from coretrace_python.plugins.secrets import config_literals
except ImportError as error:  # pragma: no cover - red until the pass lands
    MISSING: Exception | None = error
else:
    MISSING = None
    if "root" not in ProjectContext.__init__.__code__.co_varnames or not hasattr(engine, "analyze_file"):
        MISSING = AttributeError("ProjectContext.root or engine.analyze_file is missing")


@pytest.fixture(autouse=True)
def require_pass() -> None:
    if MISSING is not None:
        pytest.fail(f"config secrets and coverage are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def project(root: Path, files: dict[str, str | bytes]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
    return root


def located(findings: tuple[Finding, ...]) -> list[tuple[str, int, str, str]]:
    return sorted(
        (Path(str(f.span.source_id)).name, f.span.start_line, f.rule_id, f.metadata.get("name", ""))
        for f in findings
    )


# --------------------------------------------------------------------------- config literals


def test_config_files_yield_key_value_literals(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            ".env": "DB_PASSWORD=hunter2\nDEBUG=true\nEMPTY=\nQUOTED='with space'\n",
            "config.yaml": "service:\n  token: abc\n  - name: item\n",
            "settings.toml": '[db]\npassword = "s3cr3t"\nport = 5432\n',
            "insomnia.json": '{"resources": [{"token": "xyz", "count": 3}]}',
            "app.ini": "[main]\napi_key = k-1234\n",
            "env/pyvenv.cfg": "",
            "env/Lib/site.cfg": "password = nope\n",
            "app.py": "PASSWORD = 'py'\n",
        },
    )

    found = sorted((Path(str(span.source_id)).name, span.start_line, name, value) for value, name, span, _ in config_literals(root))

    assert found == [
        (".env", 1, "DB_PASSWORD", "hunter2"),
        (".env", 2, "DEBUG", "true"),
        (".env", 4, "QUOTED", "with space"),
        ("app.ini", 2, "api_key", "k-1234"),
        ("config.yaml", 2, "token", "abc"),
        ("config.yaml", 3, "name", "item"),
        ("insomnia.json", 1, "token", "xyz"),
        ("settings.toml", 2, "password", "s3cr3t"),
    ]


def test_config_files_honour_their_byte_order_mark(tmp_path: Path) -> None:
    root = project(tmp_path, {"export.yaml": "token: abc\n".encode("utf-16"), "app.py": "x = 1\n"})
    assert [(name, value) for value, name, _, _ in config_literals(root)] == [("token", "abc")]


# --------------------------------------------------------------------------- shipped plugin


def test_config_secrets_are_reported_with_the_python_rules(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            ".env": "DB_PASSWORD=hunter2\nDEBUG=true\nSECRET_KEY=${SECRET_KEY}\n",
            "config.yaml": f"github:\n  token: {GITHUB_TOKEN}\n",
            "insomnia.json": '{"environment": {"TOKEN": "ZmFrZS10b2tlbi12YWx1ZS1mb3ItdGVzdGluZy0xMjM0NTY3ODkw"}}',
            "app.py": "x = 1\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert located(findings) == [
        (".env", 1, "hardcoded-credential", "DB_PASSWORD"),
        ("config.yaml", 2, "hardcoded-secret", "token"),
        ("insomnia.json", 1, "hardcoded-credential", "TOKEN"),
    ]
    assert all(f.function is None for f in findings)
    assert all(GITHUB_TOKEN not in f.message and "hunter2" not in f.message for f in findings)
    assert {f.confidence for f in findings if f.rule_id == "hardcoded-secret"} == {Confidence.HIGH}


def test_python_files_are_left_to_the_module_detector(tmp_path: Path) -> None:
    root = project(tmp_path, {"settings.py": "PASSWORD = 'hunter2'\n"})
    findings = engine.analyze_project(root, [PLUGINS]).findings
    assert [(f.rule_id, f.metadata["name"]) for f in findings] == [("hardcoded-credential", "PASSWORD")]


def test_project_context_exposes_the_root(tmp_path: Path) -> None:
    root = project(tmp_path, {"app.py": "x = 1\n"})
    from coretrace_python.plugins import ProjectPlugin

    seen: list[Path] = []

    class Peek(ProjectPlugin):
        name = "peek"

        def analyze_project(self, ctx):  # type: ignore[no-untyped-def]
            seen.append(ctx.root)
            return ()

    engine.analyze_project(root, plugins=[Peek()])
    assert seen == [root]


# --------------------------------------------------------------------------- coverage


def test_coverage_counts_files_and_functions() -> None:
    coverage = Coverage(
        (
            FileCoverage("a.py", "analysed", 3, 2),
            FileCoverage("b.py", "syntax-error", 0, 0),
            FileCoverage("c.py", "unreadable", 0, 0),
            FileCoverage("d.py", "analysed", 1, 1),
        )
    )

    assert (coverage.files, coverage.files_analysed) == (4, 2)
    assert (coverage.functions, coverage.functions_analysed) == (4, 3)
    assert coverage.summary() == "coverage: 2/4 files, 3/4 functions"


def test_project_coverage_reflects_notes(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "clean.py": "def a():\n    return 1\n\ndef b():\n    return 2\n",
            "partial.py": "def ok():\n    return 1\n\ndef odd():\n    break\n",
            "broken.py": "def (:\n",
            "legacy.py": b"\xff\xfeprint('x')\n",
        },
    )

    coverage = engine.analyze_project(root, [PLUGINS]).coverage

    assert {(c.path.split("/")[-1], c.status, c.functions, c.analysed) for c in coverage.details} == {
        ("clean.py", "analysed", 2, 2),
        ("partial.py", "analysed", 2, 1),
        ("broken.py", "syntax-error", 0, 0),
        ("legacy.py", "unreadable", 0, 0),
    }
    assert coverage.summary() == "coverage: 2/4 files, 3/4 functions"


def test_single_file_analysis_carries_coverage() -> None:
    analysis = engine.analyze_file(
        SourceManager().add_source("one.py", "def a():\n    return 1\n\ndef b():\n    break\n"), [PLUGINS]
    )
    assert analysis.coverage.summary() == "coverage: 1/1 files, 1/2 functions"
    assert [f.rule_id for f in analysis.findings] == ["unsupported-syntax"]


def test_reporters_print_coverage_when_present() -> None:
    finding = Finding("r", "m", Severity.LOW, Confidence.HIGH, SourceSpan(SourceId("a.py"), 1, 1))
    coverage = Coverage((FileCoverage("a.py", "analysed", 2, 2),))

    assert render_text(Report((finding,), "t", "1")) == "a.py:1:1: low r: m\n1 finding\n"
    assert render_text(Report((finding,), "t", "1", coverage)) == (
        "a.py:1:1: low r: m\n1 finding\ncoverage: 1/1 files, 2/2 functions\n"
    )
    document = json.loads(render_json(Report((), "t", "1", coverage)))
    assert document["coverage"] == {
        "files": 1,
        "files_analysed": 1,
        "functions": 2,
        "functions_analysed": 2,
        "details": [{"path": "a.py", "status": "analysed", "functions": 2, "analysed": 2}],
    }
    assert "coverage" not in json.loads(render_json(Report((), "t", "1")))


def test_cli_prints_coverage_for_checks(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "one.py"
    source.write_text("def a():\n    return 1\n", encoding="utf-8")

    assert main(["--check", str(source), "--plugins", str(PLUGINS)]) == 0
    assert capsys.readouterr().out == "no findings\ncoverage: 1/1 files, 1/1 functions\n"
    assert main(["--check", str(tmp_path), "--plugins", str(PLUGINS), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["coverage"]["files"] == 1
