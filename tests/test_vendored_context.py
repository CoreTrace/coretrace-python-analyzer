"""Acceptance tests for issue #243: vendored code is still analysed, and its findings say
where they come from.

Code a project keeps under a ``third_party``, ``third-party``, ``vendor`` or ``vendored``
directory is someone else's: its findings carry ``origin: vendored`` in their metadata,
in the JSON report and in SARIF. The origin is told apart from the context of #244: a
vendored project's tests carry both ``context: test`` and ``origin: vendored``, so a
reader and a refiner still see why they are test code. Nothing is excluded: the
findings and the flows through vendored modules stay as they were.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding
from coretrace_python.findings.context import code_context, code_origin
from coretrace_python.reporters.sarif import render_sarif

XML_TEST = """\
from xml.dom import minidom

PASSWORD = "Zx81kQpLw0RtY7vB"
EXPECTED = "<testsuites><testsuite name='Filter'/></testsuites>"


def expected_document():
    return minidom.parseString(EXPECTED)
"""

PARSER = "from xml.dom import minidom\n\n\ndef parse(document):\n    return minidom.parseString(document)\n"
RUNNER = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
VIEWS = (
    "from flask import request\n\nfrom third_party.tools.runner import run\n\n\n"
    "def view():\n    run(request.args['c'])\n"
)


@pytest.mark.parametrize(
    ("path", "origin", "context"),
    [
        ("third_party/gtest/test/xml_output_test.py", "vendored", "test"),
        ("third-party/lib/parse.py", "vendored", None),
        ("vendor/requests/api.py", "vendored", None),
        ("src/vendored/six.py", "vendored", None),
        ("vendor/lib/tests/test_api.py", "vendored", "test"),
        ("app/vendor_api.py", None, None),
        ("external/client.py", None, None),
        ("tests/test_app.py", None, "test"),
    ],
)
def test_origin_and_context_are_told_apart(path: str, origin: str | None, context: str | None) -> None:
    assert (code_origin(path), code_context(path)) == (origin, context)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def located(findings: tuple[Finding, ...], name: str) -> dict[str, Finding]:
    return {f.rule_id: f for f in findings if Path(str(f.span.source_id)).as_posix().endswith(name)}


def situation(finding: Finding) -> tuple[str | None, str | None]:
    return finding.metadata.get("context"), finding.metadata.get("origin")


def test_vendored_findings_are_kept_and_carry_both_facts(tmp_path: Path) -> None:
    root = write(
        tmp_path / "project",
        {
            "third_party/gtest/test/xml_output_test.py": XML_TEST,
            "vendor/lib/vendored_output.py": XML_TEST,
            "app/own_output.py": XML_TEST,
        },
    )

    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    vendored_test = located(findings, "third_party/gtest/test/xml_output_test.py")
    vendored = located(findings, "vendor/lib/vendored_output.py")
    own = located(findings, "app/own_output.py")

    assert set(vendored_test) == set(vendored) == set(own) == {"hardcoded-credential", "unsafe-xml"}
    assert {rule: situation(f) for rule, f in vendored_test.items()} == dict.fromkeys(vendored_test, ("test", "vendored"))
    assert {rule: situation(f) for rule, f in vendored.items()} == dict.fromkeys(vendored, (None, "vendored"))
    assert {rule: situation(f) for rule, f in own.items()} == dict.fromkeys(own, (None, None))
    # The origin changes no verdict: the credential is low as test code, medium otherwise.
    assert vendored_test["hardcoded-credential"].confidence is Confidence.LOW
    assert vendored["hardcoded-credential"].confidence is Confidence.MEDIUM
    assert vendored["unsafe-xml"].confidence == own["unsafe-xml"].confidence


def test_a_flow_through_a_vendored_module_is_still_reported(tmp_path: Path) -> None:
    root = write(
        tmp_path / "project",
        {
            "third_party/__init__.py": "",
            "third_party/tools/__init__.py": "",
            "third_party/tools/runner.py": RUNNER,
            "app/__init__.py": "",
            "app/views.py": VIEWS,
        },
    )

    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    flows = [f for f in findings if f.rule_id == "command-injection"]

    assert [(Path(str(f.span.source_id)).name, f.span.start_line) for f in flows] == [("views.py", 7)]
    assert situation(flows[0]) == (None, None)


def test_the_sarif_result_carries_both_facts(tmp_path: Path) -> None:
    root = write(tmp_path / "project", {"vendor/lib/tests/test_output.py": XML_TEST})
    analysis = engine.analyze_project(root, [engine.BUNDLED_PLUGINS])

    results = json.loads(render_sarif(engine.report(analysis.findings, root=root)))["runs"][0]["results"]

    # Test code is reported at low confidence, which every result carries (#271).
    assert {r["ruleId"]: r["properties"] for r in results} == {
        "hardcoded-credential": {"confidence": "low", "context": "test", "origin": "vendored"},
        "unsafe-xml": {"confidence": "low", "context": "test", "origin": "vendored"},
    }


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


def test_a_refiner_still_recognises_vendored_test_code(tmp_path: Path) -> None:
    plugin = tmp_path / "plugins" / "refiner"
    plugin.mkdir(parents=True)
    (plugin / "plugin.toml").write_text(REFINER_MANIFEST, encoding="utf-8")
    (plugin / "refiner.py").write_text(REFINER, encoding="utf-8")
    root = write(
        tmp_path / "project",
        {"vendor/lib/tests/test_parser.py": PARSER, "vendor/lib/parser.py": PARSER},
    )

    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS, tmp_path / "plugins"]).findings

    assert located(findings, "vendor/lib/tests/test_parser.py")["unsafe-xml"].confidence is Confidence.LOW
    assert located(findings, "vendor/lib/parser.py")["unsafe-xml"].confidence is Confidence.HIGH
