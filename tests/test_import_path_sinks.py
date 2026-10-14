"""Acceptance tests for issue #240, part 2: the directories imports are looked up in.

``sys.path.insert``, ``append`` and ``extend`` let the input choose a directory imports
are looked up in: code runs only when a later import resolves to the attacker's module
there, so the finding is a hotspot, ``Untrusted import path``. ``site.addsitedir`` runs
the import lines of the directory's ``.pth`` files during the call: a vulnerability,
``Untrusted site directory``, exploitable when that directory holds files the attacker
controls, which the finding states. As for the import sinks, only a check that limits
the directory to constants proves it, and the environment and the command line reach
these sinks as they reach ``eval``. Writes to ``sys.path`` (slice assignment, ``+=``,
rebinding) are not calls and are not covered.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

HEADER = "import os\nimport site\nimport sys\nfrom sys import path\n\n\ndef run():\n    d = input()\n"


def injections(body: str) -> list[Finding]:
    text = HEADER + "".join(f"    {line}\n" for line in body.splitlines())
    findings = engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
    return [f for f in findings if f.rule_id == "code-injection"]


def verdict(finding: Finding) -> tuple[str, str, str]:
    return finding.metadata["verdict"], finding.confidence.value, finding.message.split(":", 1)[0]


@pytest.mark.parametrize(
    "call",
    [
        "sys.path.insert(0, d)",
        "sys.path.append(d)",
        "sys.path.extend([d])",
        "path.insert(0, d)",
    ],
)
def test_an_import_directory_the_input_chooses_is_a_hotspot(call: str) -> None:
    (finding,) = injections(call)

    assert verdict(finding) == ("hotspot", "medium", "Untrusted import path")
    assert "later import" in finding.metadata["evidence"]


@pytest.mark.parametrize("call", ["site.addsitedir(d)", "site.addsitedir(sitedir=d)"])
def test_a_site_directory_the_input_chooses_is_a_vulnerability_stating_its_condition(call: str) -> None:
    (finding,) = injections(call)

    assert verdict(finding) == ("vulnerability", "high", "Untrusted site directory")
    assert ".pth" in finding.metadata["evidence"]
    assert "attacker" in finding.metadata["evidence"]


@pytest.mark.parametrize(
    "call",
    [
        # The index is not a directory.
        "sys.path.insert(int(d), '/srv/lib')",
        "sys.path.insert(len(d), '/srv/lib')",
        # Constants and the project's own directories.
        "sys.path.insert(0, '/srv/lib')",
        "sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))",
        "site.addsitedir('/srv/site')",
    ],
)
def test_a_directory_the_input_does_not_choose_is_not_reported(call: str) -> None:
    assert injections(call) == []


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("sys.path.insert(0, d)", ("hotspot", "medium", "Untrusted import path")),
        ("site.addsitedir(d)", ("hotspot", "medium", "Untrusted site directory")),
    ],
)
@pytest.mark.parametrize("guard", ["d.isalnum()", "d.isidentifier()"])
def test_a_check_of_the_shape_of_the_directory_does_not_prove_it(
    call: str, expected: tuple[str, str, str], guard: str
) -> None:
    (finding,) = injections(f"if {guard}:\n    {call}")

    assert verdict(finding) == expected


@pytest.mark.parametrize("call", ["sys.path.insert(0, d)", "site.addsitedir(d)"])
@pytest.mark.parametrize("guard", ["d in ('/srv/a', '/srv/b')", "d == '/srv/a'"])
def test_a_check_against_constants_proves_the_directory(call: str, guard: str) -> None:
    assert injections(f"if {guard}:\n    {call}") == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("sys.path.insert(0, os.environ['PLUGIN_DIR'])", ("hotspot", "medium", "Untrusted import path")),
        ("site.addsitedir(sys.argv[1])", ("vulnerability", "high", "Untrusted site directory")),
    ],
)
def test_the_environment_and_the_command_line_reach_these_sinks(body: str, expected: tuple[str, str, str]) -> None:
    (finding,) = injections(body)

    assert verdict(finding) == expected
