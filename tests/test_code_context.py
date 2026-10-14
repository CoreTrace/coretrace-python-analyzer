"""Acceptance tests for issue #244: one classification of test code, shown on every
finding.

A file under a ``test``, ``tests``, ``testing``, ``fixtures`` or ``__tests__`` directory of
the project, or named ``test_*.py``, ``*_test.py`` or ``conftest.py``, is test code. Every
finding in it carries ``context: test`` in its metadata, in the JSON report and as a
property of its SARIF result, judged on its path in the project, not on where the
project sits. The context changes no verdict: what a rule does with it is the rule's,
and a refiner plugin sees it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding
from coretrace_python.findings.context import code_context
from coretrace_python.reporters.sarif import render_sarif

CHECKS = """\
from xml.dom import minidom

PASSWORD = "Zx81kQpLw0RtY7vB"
EXPECTED = "<report><status>ok</status></report>"


def status():
    return minidom.parseString(EXPECTED).documentElement.tagName


def total():
    return eval("1 + 1")
"""


@pytest.mark.parametrize(
    ("path", "context"),
    [
        ("tests/test_app.py", "test"),
        ("app/tests/helpers.py", "test"),
        ("test/conftest.py", "test"),
        ("conftest.py", "test"),
        ("app/views_test.py", "test"),
        ("fixtures/users.py", "test"),
        ("testing/factories.py", "test"),
        ("__tests__/views.py", "test"),
        ("app/views.py", None),
        ("app/testing_utils.py", None),
        ("app/contest.py", None),
        ("requirements.txt", None),
    ],
)
def test_test_code_is_recognised_by_its_path_in_the_project(path: str, context: str | None) -> None:
    assert code_context(path) == context


def analyse(root: Path, plugin_roots: tuple[Path, ...] = ()) -> tuple[Finding, ...]:
    return engine.analyze_project(root, [engine.BUNDLED_PLUGINS, *plugin_roots]).findings


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def by_file(findings: tuple[Finding, ...], name: str) -> dict[str, Finding]:
    return {f.rule_id: f for f in findings if Path(str(f.span.source_id)).name == name}


def test_every_finding_in_test_code_carries_the_context_and_keeps_its_verdict(tmp_path: Path) -> None:
    root = write(tmp_path / "project", {"tests/test_checks.py": CHECKS, "app/checks.py": CHECKS})

    findings = analyse(root)
    in_tests, in_app = by_file(findings, "test_checks.py"), by_file(findings, "checks.py")

    assert set(in_tests) == set(in_app) == {"hardcoded-credential", "unsafe-xml", "dangerous-eval"}
    assert {rule: f.metadata.get("context") for rule, f in in_tests.items()} == dict.fromkeys(in_tests, "test")
    assert all("context" not in f.metadata for f in in_app.values())
    for rule in ("unsafe-xml", "dangerous-eval"):
        assert (in_tests[rule].severity, in_tests[rule].confidence) == (in_app[rule].severity, in_app[rule].confidence)
    # ``hardcoded-credential`` keeps the lower confidence it already gave test code.
    assert in_tests["hardcoded-credential"].confidence is Confidence.LOW
    assert in_app["hardcoded-credential"].confidence is Confidence.MEDIUM


def test_the_context_is_judged_inside_the_project_not_on_where_it_sits(tmp_path: Path) -> None:
    text = "from xml.dom import minidom\n\n\ndef status(document):\n    return minidom.parseString(document)\n"
    root = write(tmp_path / "tests" / "project", {"app/checks.py": text})

    findings = analyse(root)

    assert [f.rule_id for f in findings] == ["unsafe-xml"]
    assert "context" not in findings[0].metadata


def test_the_sarif_result_carries_the_context(tmp_path: Path) -> None:
    root = write(tmp_path / "project", {"tests/test_checks.py": CHECKS, "app/checks.py": CHECKS})
    analysis = engine.analyze_project(root, [engine.BUNDLED_PLUGINS])

    results = json.loads(render_sarif(engine.report(analysis.findings, root=root)))["runs"][0]["results"]

    contexts = {
        (result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], result.get("properties", {}).get("context"))
        for result in results
        if result["ruleId"] == "dangerous-eval"
    }
    assert contexts == {("tests/test_checks.py", "test"), ("app/checks.py", None)}


REFINER_MANIFEST = (
    'name = "test-confidence"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = []\n\n[entrypoint]\nmodule = "refiner"\nclass = "TestConfidence"\n'
)
REFINER = '''
from dataclasses import replace
from typing import ClassVar

from coretrace_python.findings import Confidence
from coretrace_python.plugins import ProjectPlugin


class TestConfidence(ProjectPlugin):
    name: ClassVar[str] = "test-confidence"

    def analyze_project(self, ctx):
        return ()

    def refine(self, ctx, findings):
        return [
            replace(f, confidence=Confidence.LOW) if f.metadata.get("context") == "test" else f
            for f in findings
        ]
'''


def test_a_refiner_plugin_sees_the_context(tmp_path: Path) -> None:
    plugin = tmp_path / "plugins" / "refiner"
    plugin.mkdir(parents=True)
    (plugin / "plugin.toml").write_text(REFINER_MANIFEST, encoding="utf-8")
    (plugin / "refiner.py").write_text(REFINER, encoding="utf-8")
    root = write(tmp_path / "project", {"tests/test_checks.py": CHECKS, "app/checks.py": CHECKS})

    findings = analyse(root, (tmp_path / "plugins",))

    assert by_file(findings, "test_checks.py")["dangerous-eval"].confidence is Confidence.LOW
    assert by_file(findings, "checks.py")["dangerous-eval"].confidence is Confidence.HIGH
