"""OpenVEX statements from the evidence of a directory check.

``--vex PATH`` writes one statement per advisory affecting a requirement. The project is
``affected`` when its code reaches the vulnerability, reachable or exploitable, whatever
the policy or a suppression does with the finding. It is ``not_affected``
(``vulnerable_code_not_in_execute_path``) only when a curated advisory's entry points
are not reached, every file and function was analysed, and a lock file shows that no
other package requires the vulnerable one: the engine does not analyse the code of
installed packages. Anything else is ``under_investigation``, and the statement says
why.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    Condition,
    dump_advisories,
    render_vex,
)
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId

PLUGINS = engine.BUNDLED_PLUGINS
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)

CURATED = Advisory(
    "CVE-2099-0301",
    "vulnlib",
    "<1.1",
    "parse runs code from the document in unsafe mode",
    Severity.CRITICAL,
    aliases=("GHSA-aaaa-bbbb-cccc",),
    entry_points=(
        AdvisoryEntryPoint(
            SymbolId("python.vulnlib.parse"),
            "parse builds objects from tags in unsafe mode (commit abc1234)",
            (
                Condition(
                    "argument",
                    "mode is UNSAFE, the default",
                    argument="mode",
                    values=("python.vulnlib.UNSAFE",),
                    position=1,
                    default=True,
                ),
            ),
        ),
    ),
    modules=("vulnlib",),
)
UNCURATED = Advisory("CVE-2099-0302", "vulnlib", "<1.1", "a crafted document exhausts memory", Severity.MEDIUM)

PROJECT_LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "vulnlib" }]

[[package]]
name = "vulnlib"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
"""
FRAMEWORK_LOCK = PROJECT_LOCK + """
[[package]]
name = "framework"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "vulnlib" }]
"""


def vex(root: Path, app: str, files: dict[str, str] | None = None) -> dict[str, Any]:
    for relative, text in {"uv.lock": PROJECT_LOCK, "app.py": app, **(files or {})}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((CURATED, UNCURATED)), encoding="utf-8")
    analysis = engine.analyze_project(root, [PLUGINS])
    evidence = (*analysis.findings, *analysis.suppressed, *analysis.accepted)
    document = render_vex(
        analysis.dependencies, analysis.advisories, evidence, analysis.coverage, root, "coretrace", "0.6.0", NOW
    )
    return json.loads(document)  # type: ignore[no-any-return]


def statement(document: dict[str, Any], name: str) -> dict[str, Any]:
    return next(s for s in document["statements"] if s["vulnerability"]["name"] == name)


CALLED = "import vulnlib\n\ndef load(text):\n    return vulnlib.parse(text)\n"
IMPORTED = "import vulnlib\n\nMODE = vulnlib.SAFE\n"


# --------------------------------------------------------------------------- affected


def test_a_reached_entry_point_is_affected_with_where_and_what_to_do(tmp_path: Path) -> None:
    found = statement(vex(tmp_path, CALLED), "CVE-2099-0301")

    assert found["status"] == "affected"
    assert found["action_statement"] == "Update vulnlib to a version outside the vulnerable range <1.1."
    assert found["status_notes"] == "Reached by the project's code at app.py:4 python.vulnlib.parse (reachable)."


def test_attacker_input_reaching_it_is_affected_and_said_so(tmp_path: Path) -> None:
    app = "import vulnlib\n\ndef load():\n    return vulnlib.parse(input())\n"

    found = statement(vex(tmp_path, app), "CVE-2099-0301")

    assert found["status"] == "affected"
    assert found["status_notes"] == "Reached by the project's code at app.py:4 python.vulnlib.parse (exploitable)."


@pytest.mark.parametrize(
    "app, files",
    [
        (CALLED, {"coretrace-policy.toml": '[advisories]\nignore = ["CVE-2099-0301"]\n'}),
        (CALLED.replace("(text)\n", "(text)  # coretrace: ignore\n"), {}),
    ],
    ids=["accepted-by-the-policy", "suppressed-inline"],
)
def test_a_finding_the_project_accepts_or_silences_is_still_affected(
    tmp_path: Path, app: str, files: dict[str, str]
) -> None:
    assert statement(vex(tmp_path, app, files), "CVE-2099-0301")["status"] == "affected"


# --------------------------------------------------------------------------- not_affected


def test_a_curated_advisory_nothing_reaches_is_not_affected(tmp_path: Path) -> None:
    found = statement(vex(tmp_path, IMPORTED), "CVE-2099-0301")

    assert found["status"] == "not_affected"
    assert found["justification"] == "vulnerable_code_not_in_execute_path"
    assert found["impact_statement"] == (
        "No code of the project reaches the entry points of CVE-2099-0301 (python.vulnlib.parse), "
        "and no other locked package requires vulnlib."
    )


def test_calls_ruled_out_by_their_arguments_are_named_in_the_impact_statement(tmp_path: Path) -> None:
    app = "import vulnlib\n\ndef load(text):\n    return vulnlib.parse(text, vulnlib.SAFE)\n"

    found = statement(vex(tmp_path, app), "CVE-2099-0301")

    assert found["status"] == "not_affected"
    assert found["impact_statement"].endswith(
        " Calls ruled out by their arguments: app:4 python.vulnlib.parse(mode=python.vulnlib.SAFE)."
    )


# --------------------------------------------------------------------------- under_investigation


def test_an_advisory_naming_no_entry_point_stays_under_investigation(tmp_path: Path) -> None:
    found = statement(vex(tmp_path, IMPORTED), "CVE-2099-0302")

    assert found["status"] == "under_investigation"
    assert found["status_notes"] == (
        "The advisory names no entry point, so whether the project reaches the vulnerable code is not known."
    )


def test_a_package_another_locked_package_requires_stays_under_investigation(tmp_path: Path) -> None:
    found = statement(vex(tmp_path, IMPORTED, {"uv.lock": FRAMEWORK_LOCK}), "CVE-2099-0301")

    assert found["status"] == "under_investigation"
    assert found["status_notes"] == (
        "No code of the project reaches the entry points of CVE-2099-0301 (python.vulnlib.parse), "
        "but vulnlib is required by framework, whose code is not analysed."
    )


def test_without_a_lock_file_it_stays_under_investigation(tmp_path: Path) -> None:
    files = {"uv.lock": "version = 1\n", "requirements.txt": "vulnlib==1.0\n"}

    found = statement(vex(tmp_path, IMPORTED, files), "CVE-2099-0301")

    assert found["status"] == "under_investigation"
    assert found["status_notes"].endswith(
        "but no lock file shows which installed packages require vulnlib, and their code is not analysed."
    )


def test_an_incomplete_analysis_stays_under_investigation(tmp_path: Path) -> None:
    found = statement(vex(tmp_path, IMPORTED, {"broken.py": "def f(:\n"}), "CVE-2099-0301")

    assert found["status"] == "under_investigation"
    assert found["status_notes"] == (
        "No analysed code reaches the entry points of CVE-2099-0301 (python.vulnlib.parse), "
        "but broken.py could not be fully analysed."
    )


# --------------------------------------------------------------------------- document


def test_the_document_is_openvex_about_the_project_and_its_dependency(tmp_path: Path) -> None:
    document = vex(tmp_path, CALLED)

    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["@id"].startswith("https://openvex.dev/docs/public/vex-")
    assert document["author"] == "Unknown Author"
    assert document["timestamp"] == "2026-09-24T12:00:00Z"
    assert document["version"] == 1
    assert document["tooling"] == "coretrace 0.6.0"
    assert [s["vulnerability"]["name"] for s in document["statements"]] == ["CVE-2099-0301", "CVE-2099-0302"]
    found = statement(document, "CVE-2099-0301")
    assert found["vulnerability"] == {
        "name": "CVE-2099-0301",
        "description": "parse runs code from the document in unsafe mode",
        "aliases": ["GHSA-aaaa-bbbb-cccc"],
    }
    assert found["products"] == [
        {"@id": f"pkg:generic/{tmp_path.name}", "subcomponents": [{"@id": "pkg:pypi/vulnlib@1.0"}]}
    ]


def test_the_document_identifier_depends_on_the_statements_not_the_time(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "uv.lock").write_text(PROJECT_LOCK, encoding="utf-8")
    (root / "app.py").write_text(CALLED, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((CURATED,)), encoding="utf-8")
    analysis = engine.analyze_project(root, [PLUGINS])

    def identifier(evidence: tuple[Any, ...], when: datetime) -> str:
        document = render_vex(
            analysis.dependencies, analysis.advisories, evidence, analysis.coverage, root, "coretrace", "0.6.0", when
        )
        return json.loads(document)["@id"]  # type: ignore[no-any-return]

    later = datetime(2027, 1, 1, tzinfo=UTC)
    assert identifier(analysis.findings, NOW) == identifier(analysis.findings, later)
    assert identifier(analysis.findings, NOW) != identifier((), NOW)


def test_advisories_affecting_no_requirement_have_no_statement(tmp_path: Path) -> None:
    safe = PROJECT_LOCK.replace('version = "1.0"', 'version = "1.1"')

    assert vex(tmp_path, CALLED, {"uv.lock": safe})["statements"] == []


# --------------------------------------------------------------------------- CLI


def test_check_writes_the_vex_document_next_to_the_report(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "src"
    root.mkdir()
    (root / "uv.lock").write_text(PROJECT_LOCK, encoding="utf-8")
    (root / "app.py").write_text(CALLED, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((CURATED,)), encoding="utf-8")
    path = tmp_path / "vex.json"

    code = main(["--check", str(root), "--plugins", str(PLUGINS), "--vex", str(path)])

    assert code == 1
    assert "reachable-vulnerability" in capsys.readouterr().out
    document = json.loads(path.read_text(encoding="utf-8"))
    assert [(s["vulnerability"]["name"], s["status"]) for s in document["statements"]] == [("CVE-2099-0301", "affected")]
    assert document["timestamp"].endswith("Z")


def test_vex_option_requires_a_directory_check(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "x.py"
    source.write_text("", encoding="utf-8")

    assert main(["--check", "--vex", str(tmp_path / "vex.json"), str(source)]) == 2
    assert "--vex" in capsys.readouterr().err
