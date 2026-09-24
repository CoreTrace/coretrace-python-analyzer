"""An advisory entry point reached by reading it, not only by calling it.

Some vulnerable code runs when an attribute is read: Werkzeug parses a multipart body
when ``request.form``, ``request.files`` or ``request.data`` is read. An entry point
marked ``read`` is reached by any read of it or of an attribute of it — a subscript, an
iteration, a method call on it all read it first — while an ordinary entry point is
still reached by a call only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    AdvisoryFileError,
    dump_advisories,
    load_advisories,
)
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId

PLUGINS = engine.BUNDLED_PLUGINS
PARSED = "the getter parses the whole body (commit abc1234)"

FORM = Advisory(
    "CVE-2099-0201",
    "vulnlib",
    "<1.1",
    "reading the form parses an unbounded body",
    Severity.HIGH,
    entry_points=(
        AdvisoryEntryPoint(SymbolId("python.vulnlib.request.form"), PARSED, read=True),
        AdvisoryEntryPoint(SymbolId("python.vulnlib.request.files"), PARSED, read=True),
        AdvisoryEntryPoint(SymbolId("python.vulnlib.parse"), "parse parses the body (commit abc1234)"),
    ),
    modules=("vulnlib",),
)


def analyse(root: Path, body: str, **options: object) -> engine.ProjectAnalysis:
    files = {
        "requirements.txt": "vulnlib==1.0\n",
        "app.py": f"from vulnlib import request, parse\nimport vulnlib\n\ndef view():\n{body}",
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((FORM,)), encoding="utf-8")
    return engine.analyze_project(root, [PLUGINS], **options)  # type: ignore[arg-type]


def reached(analysis: engine.ProjectAnalysis) -> list[tuple[int, str]]:
    return [
        (f.span.start_line, f.metadata["entry_point"])
        for f in analysis.findings
        if f.rule_id == "reachable-vulnerability"
    ]


@pytest.mark.parametrize(
    "body, entry",
    [
        ("    return request.form['name']\n", "python.vulnlib.request.form"),
        ("    for upload in request.files:\n        pass\n", "python.vulnlib.request.files"),
        ("    return request.form.get('name')\n", "python.vulnlib.request.form"),
        ("    form = vulnlib.request.form\n    return form\n", "python.vulnlib.request.form"),
    ],
)
def test_reading_an_entry_point_marked_read_reaches_it(tmp_path: Path, body: str, entry: str) -> None:
    assert reached(analyse(tmp_path, body)) == [(5, entry)]


def test_several_reads_of_one_entry_point_in_a_function_are_one_finding(tmp_path: Path) -> None:
    body = "    first = request.form['a']\n    second = request.form['b']\n    return first, request.form.get('c')\n"

    assert reached(analyse(tmp_path, body)) == [(5, "python.vulnlib.request.form")]


def test_calling_an_entry_point_marked_read_is_one_finding(tmp_path: Path) -> None:
    assert reached(analyse(tmp_path, "    return request.files()\n")) == [(5, "python.vulnlib.request.files")]


def test_an_entry_point_not_marked_read_is_still_reached_by_a_call_only(tmp_path: Path) -> None:
    assert reached(analyse(tmp_path / "referenced", "    handler = parse\n    return handler\n")) == []
    assert reached(analyse(tmp_path / "called", "    return parse(request)\n")) == [(5, "python.vulnlib.parse")]


def test_a_module_served_from_the_cache_still_reaches_what_it_reads(tmp_path: Path) -> None:
    cache = ProjectCache(tmp_path / "cache")
    body = "    return request.form['name']\n"

    first = analyse(tmp_path / "src", body, cache=cache)
    second = analyse(tmp_path / "src", body, cache=cache)

    assert "app" in second.reused
    assert reached(second) == reached(first) == [(5, "python.vulnlib.request.form")]


def test_read_entry_points_round_trip_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((FORM,)), encoding="utf-8")

    assert load_advisories(path) == (FORM,)
    entries = json.loads(path.read_text(encoding="utf-8"))["advisories"][0]["entry_points"]
    assert [entry.get("read") for entry in entries] == [True, True, None]


def test_a_malformed_read_flag_is_rejected(tmp_path: Path) -> None:
    document = json.loads(dump_advisories((FORM,)))
    document["advisories"][0]["entry_points"][0]["read"] = "yes"
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError, match="read"):
        load_advisories(path)
