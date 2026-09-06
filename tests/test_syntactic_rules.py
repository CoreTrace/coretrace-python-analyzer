"""Acceptance tests for five syntactic rules (issue #70).

Cheap checks in the spirit of ``dangerous-eval``: disabled certificate verification,
XML parsers that expand entities, archive extraction without member checks, ``mktemp``,
and ``random`` used to build secrets. Each is a call to a known symbol, resolved through
imports, aliases and call chains (``tarfile.open(p).extractall()``), with a keyword check
where the same call has a safe form (``verify=True``, ``filter="data"``).

Expected to remain red until the five plugins exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.source import SourceManager

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"
NAMES = ("insecure_tls", "unsafe_xml", "unsafe_archive", "insecure_tempfile", "weak_random")
MISSING = [n for n in NAMES if not (PLUGINS / "syntax" / n / "plugin.toml").is_file()] or None


@pytest.fixture(autouse=True)
def require_rules() -> None:
    if MISSING is not None:
        pytest.fail(f"syntactic rule plugins are not written yet: {MISSING}")


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings if f.rule_id != "missing-timeout")


def test_disabled_certificate_verification() -> None:
    (finding,) = check("import requests\n\ndef f(u):\n    return requests.get(u, verify=False, timeout=3)\n")
    assert finding.rule_id == "insecure-tls" and finding.severity is Severity.HIGH
    assert rules(check("import httpx\n\ndef f(u):\n    with httpx.Client(verify=False) as c:\n        return c.get(u, timeout=3)\n")) == ["insecure-tls"]
    assert rules(check("import ssl\n\ndef f():\n    return ssl._create_unverified_context()\n")) == ["insecure-tls"]
    assert check("import requests\n\ndef f(u, v):\n    requests.get(u, verify=True, timeout=3)\n    requests.get(u, verify=v, timeout=3)\n") == ()


def test_xml_parsers_that_expand_entities() -> None:
    text = (
        "import xml.etree.ElementTree as ET\nfrom xml.dom import minidom\nimport xml.sax\nfrom lxml import etree\n\n"
        "def f(data):\n    ET.fromstring(data)\n    minidom.parseString(data)\n    xml.sax.parseString(data, None)\n    etree.fromstring(data)\n"
    )
    assert rules(check(text)) == ["unsafe-xml"] * 4
    assert check("import defusedxml.ElementTree as ET\n\ndef f(data):\n    ET.fromstring(data)\n") == ()


def test_archive_extraction_without_member_checks() -> None:
    text = "import tarfile\nimport zipfile\nimport shutil\n\ndef f(p):\n    tarfile.open(p).extractall('/tmp/x')\n    zipfile.ZipFile(p).extractall('/tmp/x')\n    shutil.unpack_archive(p, '/tmp/x')\n"
    assert rules(check(text)) == ["unsafe-archive-extraction"] * 3
    text = "import tarfile\n\ndef f(p):\n    with tarfile.open(p) as tar:\n        tar.extractall('/tmp/x', filter='data')\n"
    assert check(text) == ()
    text = "import tarfile\n\ndef f(p):\n    with tarfile.open(p) as tar:\n        tar.extractall('/tmp/x')\n"
    assert rules(check(text)) == ["unsafe-archive-extraction"]


def test_insecure_temporary_files() -> None:
    assert rules(check("import tempfile\n\ndef f():\n    return tempfile.mktemp()\n")) == ["insecure-temp-file"]
    assert check("import tempfile\n\ndef f():\n    return tempfile.mkstemp()\n") == ()


def test_random_used_for_secrets() -> None:
    text = "import random\nimport string\n\ndef make():\n    token = ''.join(random.choice(string.ascii_letters) for _ in range(32))\n    return token\n"
    (finding,) = check(text)
    assert finding.rule_id == "weak-random" and finding.confidence is Confidence.MEDIUM
    assert rules(check("import random\n\ndef generate_api_key():\n    return random.getrandbits(128)\n")) == ["weak-random"]
    assert rules(check("import random\n\nclass S:\n    def reset(self):\n        self.session_id = random.randint(0, 10**9)\n")) == ["weak-random"]
    assert check("import random\n\ndef shuffle(cards):\n    random.shuffle(cards)\n    delay = random.uniform(1, 3)\n    return delay\n") == ()
    assert check("import secrets\n\ndef make():\n    token = secrets.token_hex(16)\n    return token\n") == ()
