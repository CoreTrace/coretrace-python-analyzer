"""Acceptance tests for issue #243: vendored code is still analysed, and its findings say
where they are.

Code a project keeps under a ``third_party``, ``third-party``, ``vendor`` or ``vendored``
directory is someone else's: its findings carry ``context: vendored`` (the context of
#244), in the JSON report and in SARIF, over any other context, test code of the vendored
project included. Nothing is excluded: the findings and the flows through vendored
modules stay as they were.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.findings.context import code_context
from coretrace_python.reporters.sarif import render_sarif

XML_TEST = """\
from xml.dom import minidom

PASSWORD = "Zx81kQpLw0RtY7vB"
EXPECTED = "<testsuites><testsuite name='Filter'/></testsuites>"


def expected_document():
    return minidom.parseString(EXPECTED)
"""

RUNNER = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
VIEWS = (
    "from flask import request\n\nfrom third_party.tools.runner import run\n\n\n"
    "def view():\n    run(request.args['c'])\n"
)


@pytest.mark.parametrize(
    ("path", "context"),
    [
        ("third_party/gtest/test/xml_output_test.py", "vendored"),
        ("third-party/lib/parse.py", "vendored"),
        ("vendor/requests/api.py", "vendored"),
        ("src/vendored/six.py", "vendored"),
        ("tests/vendor/test_api.py", "vendored"),
        ("app/vendor_api.py", None),
        ("external/client.py", None),
        ("tests/test_app.py", "test"),
    ],
)
def test_vendored_code_is_recognised_by_its_path_in_the_project(path: str, context: str | None) -> None:
    assert code_context(path) == context


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def located(findings: tuple[Finding, ...], name: str) -> list[Finding]:
    return [f for f in findings if Path(str(f.span.source_id)).as_posix().endswith(name)]


def test_vendored_findings_are_kept_and_carry_the_context(tmp_path: Path) -> None:
    root = write(
        tmp_path / "project",
        {"third_party/gtest/test/xml_output_test.py": XML_TEST, "app/xml_output.py": XML_TEST},
    )

    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    vendored = {f.rule_id: f for f in located(findings, "third_party/gtest/test/xml_output_test.py")}
    own = {f.rule_id: f for f in located(findings, "app/xml_output.py")}

    assert set(vendored) == set(own) == {"hardcoded-credential", "unsafe-xml"}
    assert {rule: f.metadata.get("context") for rule, f in vendored.items()} == dict.fromkeys(vendored, "vendored")
    assert vendored["unsafe-xml"].confidence == own["unsafe-xml"].confidence
    # The rule still judges the credential as test code, at low confidence; the vendored
    # context is the one shown.
    assert vendored["hardcoded-credential"].confidence.value == "low"


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
    assert "context" not in flows[0].metadata


def test_the_sarif_result_carries_the_vendored_context(tmp_path: Path) -> None:
    root = write(tmp_path / "project", {"vendor/lib/xml_output.py": XML_TEST})
    analysis = engine.analyze_project(root, [engine.BUNDLED_PLUGINS])

    results = json.loads(render_sarif(engine.report(analysis.findings, root=root)))["runs"][0]["results"]

    assert {r["ruleId"]: r["properties"]["context"] for r in results} == {
        "hardcoded-credential": "vendored",
        "unsafe-xml": "vendored",
    }
