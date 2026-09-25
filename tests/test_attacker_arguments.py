"""An advisory entry point may name the arguments the attacker must control.

Most vulnerabilities need attacker input in one argument: the path ``send_from_directory``
serves, not its ``download_name``; the URL ``requests.get`` fetches, not its body. An
entry point naming its ``attacker_arguments`` — by keyword and, when they may be passed
positionally, by ``position``; a ``variadic`` one takes every position from its own on —
is exploitable only when attacker input reaches one of them, and stays reachable
otherwise. An argument unpacked with ``*`` or ``**`` may fill any of them: like an
argument condition it leaves undecided, it does not rule the call out, so it counts. An
entry point naming none counts every argument, as before.
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

PLUGINS = engine.BUNDLED_PLUGINS
CRAFTED = (Condition("semantic", "the URL is crafted to split its host"),)
URL = (AttackerArgument("url", 0),)

FETCH = Advisory(
    "CVE-2099-0601",
    "vulnlib",
    "<1.1",
    "fetch sends the credentials of one host to another for a crafted URL",
    Severity.HIGH,
    entry_points=(
        AdvisoryEntryPoint(SymbolId("python.vulnlib.fetch"), "commit abc1234", CRAFTED, attacker_arguments=URL),
        AdvisoryEntryPoint(
            SymbolId("python.vulnlib.Session.fetch"),
            "call path: Session.fetch -> fetch (commit abc1234)",
            CRAFTED,
            attacker_arguments=URL,
        ),
    ),
    modules=("vulnlib",),
)
JOIN = Advisory(
    "CVE-2099-0602",
    "vulnlib",
    "<1.1",
    "join accepts device names among the parts it joins",
    Severity.MEDIUM,
    entry_points=(
        AdvisoryEntryPoint(
            SymbolId("python.vulnlib.join"),
            "commit def5678",
            (Condition("semantic", "the server runs on Windows"),),
            attacker_arguments=(AttackerArgument(position=1, variadic=True),),
        ),
    ),
    modules=("vulnlib",),
)
SLOW = Advisory(
    "CVE-2099-0603",
    "vulnlib",
    "<1.1",
    "fetch is slow on any large argument",
    Severity.LOW,
    entry_points=(
        AdvisoryEntryPoint(
            SymbolId("python.vulnlib.fetch"), "commit 0a1b2c3", (Condition("semantic", "the argument is large"),)
        ),
    ),
    modules=("vulnlib",),
)


def analyse(root: Path, files: dict[str, str]) -> tuple[Finding, ...]:
    for relative, text in {"requirements.txt": "vulnlib==1.0\n", **files}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((FETCH, JOIN, SLOW)), encoding="utf-8")
    return engine.analyze_project(root, [PLUGINS]).findings


def of_rule(findings: tuple[Finding, ...], rule_id: str) -> list[tuple[int, str]]:
    return sorted((f.span.start_line, f.metadata["advisory"]) for f in findings if f.rule_id == rule_id)


def exploitable(root: Path, files: dict[str, str]) -> list[tuple[int, str]]:
    return of_rule(analyse(root, files), "exploitable-vulnerability")


def calling(call: str) -> dict[str, str]:
    return {"app.py": f"import vulnlib\n\ndef run():\n    data = input()\n    return {call}\n"}


@pytest.mark.parametrize(
    "call, advisories",
    [
        ("vulnlib.fetch(data)", ["CVE-2099-0601", "CVE-2099-0603"]),
        ("vulnlib.fetch(url=data)", ["CVE-2099-0601", "CVE-2099-0603"]),
        ("vulnlib.Session().fetch(data)", ["CVE-2099-0601"]),
        ("vulnlib.join('uploads', data)", ["CVE-2099-0602"]),
        ("vulnlib.join('uploads', 'reports', data)", ["CVE-2099-0602"]),
    ],
)
def test_attacker_input_in_a_named_argument_is_exploitable(tmp_path: Path, call: str, advisories: list[str]) -> None:
    assert exploitable(tmp_path, calling(call)) == [(5, a) for a in advisories]


@pytest.mark.parametrize(
    "call, advisories, reached",
    [
        ("vulnlib.fetch('https://example.com', body=data)", ["CVE-2099-0603"], "CVE-2099-0601"),
        ("vulnlib.fetch('https://example.com', data)", ["CVE-2099-0603"], "CVE-2099-0601"),
        ("vulnlib.Session().fetch('https://example.com', body=data)", [], "CVE-2099-0601"),
        ("vulnlib.join(data, 'report.pdf')", [], "CVE-2099-0602"),
    ],
)
def test_attacker_input_in_another_argument_leaves_the_call_reachable_only(
    tmp_path: Path, call: str, advisories: list[str], reached: str
) -> None:
    found = analyse(tmp_path, calling(call))

    assert of_rule(found, "exploitable-vulnerability") == [(5, a) for a in advisories]
    assert (5, reached) in of_rule(found, "reachable-vulnerability")


@pytest.mark.parametrize(
    "call, advisories",
    [
        ("vulnlib.fetch(*data.split(','))", ["CVE-2099-0601", "CVE-2099-0603"]),
        ("vulnlib.fetch(**{'url': data})", ["CVE-2099-0601", "CVE-2099-0603"]),
        ("vulnlib.join('uploads', *data.split('/'))", ["CVE-2099-0602"]),
    ],
)
def test_an_unpacked_argument_may_fill_a_named_one_so_it_counts(tmp_path: Path, call: str, advisories: list[str]) -> None:
    assert exploitable(tmp_path, calling(call)) == [(5, a) for a in advisories]


def test_a_wrapper_forwarding_its_arguments_unpacked_still_reaches_the_named_one(tmp_path: Path) -> None:
    source = (
        "import vulnlib\n\n"
        "def fetch(*args, **kwargs):\n    return vulnlib.fetch(*args, timeout=5, **kwargs)\n\n"
        "def run():\n    fetch(input())\n"
    )

    assert exploitable(tmp_path, {"app.py": source}) == [(7, "CVE-2099-0601"), (7, "CVE-2099-0603")]


def test_the_argument_of_the_entry_point_call_decides_when_the_flow_goes_through_a_function(tmp_path: Path) -> None:
    source = (
        "import vulnlib\n\n"
        "def get(url, body):\n    return vulnlib.fetch(url, body=body)\n\n"
        "def run():\n    get('https://example.com', input())\n    get(input(), None)\n"
    )

    assert exploitable(tmp_path, {"app.py": source}) == [
        (7, "CVE-2099-0603"),
        (8, "CVE-2099-0601"),
        (8, "CVE-2099-0603"),
    ]


def test_attacker_arguments_round_trip_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((FETCH, JOIN, SLOW)), encoding="utf-8")

    assert load_advisories(path) == (FETCH, JOIN, SLOW)
    entries = [e for a in json.loads(path.read_text())["advisories"] for e in a["entry_points"]]
    assert entries[0]["attacker_arguments"] == [{"argument": "url", "position": 0}]
    assert entries[2]["attacker_arguments"] == [{"position": 1, "variadic": True}]
    assert "attacker_arguments" not in entries[3]


@pytest.mark.parametrize(
    "arguments",
    [
        [{}],
        [{"position": -1}],
        [{"position": True}],
        [{"argument": "url", "variadic": True}],
        [{"position": 1, "variadic": "yes"}],
        [{"argument": 7}],
    ],
)
def test_a_malformed_attacker_argument_is_rejected(tmp_path: Path, arguments: list[object]) -> None:
    document = json.loads(dump_advisories((FETCH,)))
    document["advisories"][0]["entry_points"][0]["attacker_arguments"] = arguments
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError):
        load_advisories(path)
