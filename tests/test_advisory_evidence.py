"""What an advisory says beyond a version range, and what a finding keeps of it.

An advisory names the internal ``affected_symbols`` the fix changed and the public
``entry_points`` through which a project reaches them, each justified by the commit or
by a call path and carrying the ``conditions`` under which it is reached or exploited.
A condition the engine cannot check yet is kept as pending review, never dropped.
Every dependency finding records the highest level of evidence established for it:
``declared`` (the requirement allows a vulnerable version), ``imported`` (a module of
the package is imported), ``reachable`` (an entry point or affected symbol is called),
``exploitable`` (attacker input reaches it).
"""

from __future__ import annotations

import json
from pathlib import Path

from coretrace_python import engine
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    Condition,
    dump_advisories,
    load_advisories,
)
from coretrace_python.findings import Finding, Severity
from coretrace_python.semantic.symbols import SymbolId

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

ADVISORY = Advisory(
    "CVE-2099-0001",
    "vulnlib",
    "<1.1",
    "parse runs code from the document in unsafe mode",
    Severity.CRITICAL,
    affected_symbols=(SymbolId("python.vulnlib._parser.parse_unsafe"),),
    entry_points=(
        AdvisoryEntryPoint(
            SymbolId("python.vulnlib.parse"),
            "calls _parser.parse_unsafe when mode is UNSAFE (commit 1234abc)",
            (
                Condition("argument", "mode is UNSAFE, the default", argument="mode", values=("python.vulnlib.UNSAFE",)),
                Condition("semantic", "the document carries a custom tag"),
            ),
        ),
    ),
    modules=("vulnlib",),
)


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    return root


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return sorted((Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings)


def by_rule(findings: tuple[Finding, ...], rule_id: str) -> Finding:
    return next(f for f in findings if f.rule_id == rule_id)


# --------------------------------------------------------------------------- schema


def test_advisory_files_keep_entry_points_conditions_and_modules(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    assert load_advisories(path) == (ADVISORY,)
    entry = json.loads(path.read_text(encoding="utf-8"))["advisories"][0]
    assert entry["modules"] == ["vulnlib"]
    assert entry["entry_points"][0]["symbol"] == "python.vulnlib.parse"
    assert entry["entry_points"][0]["justification"].startswith("calls _parser.parse_unsafe")
    assert entry["entry_points"][0]["conditions"][1] == {"kind": "semantic", "text": "the document carries a custom tag"}


def test_modules_default_to_the_package_name() -> None:
    assert Advisory("X", "python-jose", "<1", "s", Severity.LOW).modules == ("python_jose",)


# --------------------------------------------------------------------------- the four levels


def test_a_required_package_nobody_imports_is_declared_only(tmp_path: Path) -> None:
    root = project(tmp_path, {"requirements.txt": "vulnlib==1.0\n", "app.py": "import os\n"})

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("requirements.txt", "vulnerable-dependency", 1)]
    assert findings[0].metadata["level"] == "declared"


def test_an_imported_package_without_a_call_is_imported_not_reachable(tmp_path: Path) -> None:
    root = project(tmp_path, {"requirements.txt": "vulnlib==1.0\n", "app.py": "import vulnlib\n\nSAFE = vulnlib.SAFE\n"})

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("requirements.txt", "vulnerable-dependency", 1)]
    assert findings[0].metadata["level"] == "imported"


def test_a_call_to_an_entry_point_is_reachable_with_its_justification_and_conditions(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "vulnlib==1.0\n", "app.py": "import vulnlib\n\ndef load(text):\n    return vulnlib.parse(text)\n"},
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("app.py", "reachable-vulnerability", 4), ("requirements.txt", "vulnerable-dependency", 1)]
    reachable = by_rule(findings, "reachable-vulnerability")
    assert reachable.metadata["level"] == "reachable"
    assert reachable.metadata["entry_point"] == "python.vulnlib.parse"
    assert reachable.metadata["justification"].startswith("calls _parser.parse_unsafe")
    assert reachable.metadata["conditions"] == "mode is UNSAFE, the default; the document carries a custom tag"
    assert "the document carries a custom tag" in reachable.metadata["conditions_pending_review"]
    assert by_rule(findings, "vulnerable-dependency").metadata["level"] == "imported"


def test_a_call_to_an_affected_symbol_itself_is_reachable_too(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "vulnlib==1.0\n",
            "app.py": "from vulnlib._parser import parse_unsafe\n\ndef load(text):\n    return parse_unsafe(text)\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    reachable = by_rule(findings, "reachable-vulnerability")
    assert reachable.metadata["symbol"] == "python.vulnlib._parser.parse_unsafe"
    assert reachable.metadata["justification"] == "affected symbol, changed by the fix"
    assert "entry_point" not in reachable.metadata


def test_attacker_input_reaching_an_entry_point_is_exploitable(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "vulnlib==1.0\n", "app.py": "import vulnlib\n\ndef load():\n    return vulnlib.parse(input())\n"},
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    exploitable = by_rule(findings, "exploitable-vulnerability")
    assert exploitable.metadata["level"] == "exploitable"
    assert exploitable.metadata["entry_point"] == "python.vulnlib.parse"
    assert exploitable.metadata["conditions_pending_review"] != ""
    assert by_rule(findings, "reachable-vulnerability").metadata["level"] == "reachable"


# --------------------------------------------------------------------------- several advisories on one symbol


def test_every_advisory_matching_a_call_is_reported(tmp_path: Path) -> None:
    second = Advisory(
        "CVE-2099-0002",
        "vulnlib",
        "<1.0.5",
        "parse leaks memory on a crafted document",
        Severity.HIGH,
        entry_points=(AdvisoryEntryPoint(SymbolId("python.vulnlib.parse"), "parse reads the document (commit 9abc)"),),
        modules=("vulnlib",),
    )
    root = project(
        tmp_path,
        {"requirements.txt": "vulnlib==1.0\n", "app.py": "import vulnlib\n\ndef load():\n    return vulnlib.parse(input())\n"},
    )
    (root / "advisories.json").write_text(dump_advisories((ADVISORY, second)), encoding="utf-8")

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert sorted(f.metadata["advisory"] for f in findings if f.rule_id == "reachable-vulnerability") == [
        "CVE-2099-0001",
        "CVE-2099-0002",
    ]
    assert sorted(f.metadata["advisory"] for f in findings if f.rule_id == "exploitable-vulnerability") == [
        "CVE-2099-0001",
        "CVE-2099-0002",
    ]
