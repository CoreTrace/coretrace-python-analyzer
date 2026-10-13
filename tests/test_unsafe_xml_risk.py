"""Acceptance tests for issue #242: ``unsafe-xml`` says what each parser family risks.

The standard library's parsers run on Expat, which never reads a local file; they expand
the entities a document declares, which can exhaust memory with Expat older than 2.7.2.
lxml resolves external entities by default before 5.0, and for ``iterparse`` and
``ETCompatXMLParser`` before 6.1 (CVE-2026-41066); ``resolve_entities=True`` resolves them
whatever the version, ``False`` or ``'internal'`` never. A document the project wrote
itself is no attacker's: it is reported at low confidence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"


def check(text: str) -> tuple[Finding, ...]:
    findings = engine.check(SourceManager().add_source("m.py", text), [PLUGINS])
    return tuple(f for f in findings if f.rule_id == "unsafe-xml")


def only(text: str) -> Finding:
    (finding,) = check(text)
    assert finding.severity is Severity.MEDIUM
    return finding


@pytest.mark.parametrize(
    "call",
    [
        "xml.etree.ElementTree.fromstring(data)",
        "xml.dom.minidom.parseString(data)",
        "xml.sax.parseString(data, None)",
    ],
)
def test_a_standard_library_parser_is_reported_for_entity_amplification(call: str) -> None:
    finding = only(f"import xml.etree.ElementTree\nimport xml.dom.minidom\nimport xml.sax\n\ndef f(data):\n    {call}\n")

    assert "Expat older than 2.7.2" in finding.message
    assert "local file" not in finding.message
    assert finding.confidence is Confidence.HIGH


@pytest.mark.parametrize("function", ["fromstring", "parse", "XML", "XMLParser"])
def test_an_lxml_parser_with_its_defaults_is_reported_for_versions_before_5(function: str) -> None:
    finding = only(f"import lxml.etree\n\ndef f(data):\n    lxml.etree.{function}(data)\n")

    assert "before lxml 5.0" in finding.message
    assert "local files" in finding.message


@pytest.mark.parametrize("function", ["iterparse", "ETCompatXMLParser"])
def test_iterparse_and_the_compatibility_parser_are_reported_for_versions_before_6_1(function: str) -> None:
    finding = only(f"import lxml.etree\n\ndef f(data):\n    lxml.etree.{function}(data)\n")

    assert "before lxml 6.1" in finding.message
    assert "CVE-2026-41066" in finding.message


def test_resolving_entities_explicitly_is_reported_whatever_the_version() -> None:
    finding = only("import lxml.etree\n\ndef f(data):\n    lxml.etree.XMLParser(resolve_entities=True)\n")

    assert "resolve_entities=True" in finding.message
    assert "before lxml" not in finding.message


@pytest.mark.parametrize("value", ["False", "'internal'"])
def test_a_parser_that_resolves_no_external_entity_is_not_reported(value: str) -> None:
    assert check(f"import lxml.etree\n\ndef f(data):\n    lxml.etree.XMLParser(resolve_entities={value})\n") == ()
    assert check(f"import lxml.etree\n\ndef f(data):\n    lxml.etree.iterparse(data, resolve_entities={value})\n") == ()


@pytest.mark.parametrize(
    "text",
    [
        "from xml.dom import minidom\n\ndef f():\n    minidom.parseString('<report/>')\n",
        "from xml.dom import minidom\nEXPECTED = '<report/>'\n\ndef f():\n    minidom.parseString(EXPECTED)\n",
        "import lxml.etree\n\ndef f():\n    lxml.etree.parse('settings.xml')\n",
    ],
)
def test_a_document_the_project_wrote_is_reported_at_low_confidence(text: str) -> None:
    assert only(text).confidence is Confidence.LOW


def test_a_document_of_unknown_origin_keeps_high_confidence() -> None:
    text = "from xml.dom import minidom\nEXPECTED = '<report/>'\nEXPECTED = load()\n\ndef f():\n    minidom.parseString(EXPECTED)\n"

    assert only(text).confidence is Confidence.HIGH
