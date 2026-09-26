"""An advisory entry point may declare that exploiting it needs the attacker to choose the
host of a URL: a ``host`` condition naming the argument. The engine decides it from what
the URL's constant text proves (``taint.urls``), the proof ``ssrf`` and ``open-redirect``
read, with the advisory's own criteria:

- constant text fixing the host, and the call disabling redirects: the attacker cannot
  choose the host, so the call is reachable, not exploitable;
- constant text fixing the host, redirects followed: the initial host does not clear the
  chain, since a redirect may lead to a host the attacker controls. The call stays
  exploitable, and the condition pending review says so. Input in the query does not
  choose the host;
- anything else: the condition stays pending review, undecided.

The other conditions, those on the environment included, stay pending as before.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    AdvisoryFileError,
    AttackerArgument,
    Condition,
    dump_advisories,
    load_advisories,
)
from coretrace_python.findings import Finding, Severity
from coretrace_python.semantic.symbols import SymbolId

HOST = Condition("host", "the attacker chooses the host of the URL", argument="url", position=0)
NETRC = Condition("semantic", "a .netrc file holds credentials for the host")
FETCH = Advisory(
    "CVE-2099-0901",
    "vulnlib",
    "<1.1",
    "fetch sends the credentials of one host to another",
    Severity.HIGH,
    entry_points=(
        AdvisoryEntryPoint(
            SymbolId("python.vulnlib.fetch"),
            "commit abc1234",
            (HOST, NETRC),
            attacker_arguments=(AttackerArgument("url", 0),),
        ),
    ),
    modules=("vulnlib",),
)
FIXED = "the host is fixed by 'https://api.example.com/', but a redirect may lead to a host the attacker controls"


def analyse(root: Path, call: str) -> tuple[Finding, ...]:
    (root / "requirements.txt").write_text("vulnlib==1.0\n", encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((FETCH,)), encoding="utf-8")
    (root / "app.py").write_text(
        f"import vulnlib\n\ndef run():\n    data = input()\n    return {call}\n", encoding="utf-8"
    )
    return engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings


def exploitable(root: Path, call: str) -> list[str]:
    """The conditions pending review of each exploitable finding."""

    return [
        f.metadata.get("conditions_pending_review", "")
        for f in analyse(root, call)
        if f.rule_id == "exploitable-vulnerability"
    ]


@pytest.mark.parametrize(
    "call",
    [
        "vulnlib.fetch(data)",
        # The host is left open: ``data='@evil.example'`` chooses it.
        "vulnlib.fetch('https://api.example.com' + data, allow_redirects=False)",
        "vulnlib.fetch(BASE + data)",
    ],
)
def test_a_host_not_proven_fixed_leaves_the_condition_pending(tmp_path: Path, call: str) -> None:
    assert exploitable(tmp_path, call) == [f"{HOST.text}; {NETRC.text}"]


@pytest.mark.parametrize(
    "call",
    [
        "vulnlib.fetch('https://api.example.com/users/' + data)",
        # Input in the query does not choose the host either.
        "vulnlib.fetch(f'https://api.example.com/search?q={data}')",
    ],
)
def test_a_fixed_host_with_redirects_followed_keeps_the_chain_visible(tmp_path: Path, call: str) -> None:
    assert exploitable(tmp_path, call) == [f"{FIXED}; {NETRC.text}"]


@pytest.mark.parametrize(
    "call",
    [
        "vulnlib.fetch('https://api.example.com/users/' + data, allow_redirects=False)",
        "vulnlib.fetch(url='https://api.example.com/users/' + data, follow_redirects=False)",
    ],
)
def test_a_fixed_host_without_redirects_leaves_the_call_reachable_only(tmp_path: Path, call: str) -> None:
    findings = analyse(tmp_path, call)

    assert [f for f in findings if f.rule_id == "exploitable-vulnerability"] == []
    assert [f.metadata["advisory"] for f in findings if f.rule_id == "reachable-vulnerability"] == [FETCH.id]


def test_host_conditions_round_trip_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((FETCH,)), encoding="utf-8")

    assert load_advisories(path) == (FETCH,)
    (entry,) = json.loads(path.read_text())["advisories"][0]["entry_points"]
    assert entry["conditions"][0] == {
        "kind": "host",
        "text": "the attacker chooses the host of the URL",
        "argument": "url",
        "position": 0,
    }


@pytest.mark.parametrize(
    "condition",
    [
        {"kind": "host", "text": "the attacker chooses the host"},
        {"kind": "host", "text": "the attacker chooses the host", "argument": "url", "values": ["x"]},
        {"kind": "host", "text": "the attacker chooses the host", "argument": "url", "default": True},
    ],
)
def test_a_host_condition_names_its_argument_and_nothing_else(tmp_path: Path, condition: dict[str, object]) -> None:
    document = json.loads(dump_advisories((FETCH,)))
    document["advisories"][0]["entry_points"][0]["conditions"] = [condition]
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError):
        load_advisories(path)
