"""Acceptance tests for ``nonlocal`` writes flowing back to the enclosing function (issue #71).

A nested function that declares ``nonlocal name`` and assigns it rebinds the enclosing
function's variable when it is called. The lowering of the enclosing function emits, after
a call to such a nested function it defined, a ``nonlocal_result`` per written name and
stores it into the variable; the nested function's summary records what it stores into
each nonlocal, and the dependence and taint engines read that back at the call.

Expected to remain red until ``ir.model.NonlocalResult`` and ``FunctionSummary.nonlocal_writes`` exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.interprocedural import FunctionSummary
from coretrace_python.ir import model
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.source import SourceManager

MISSING = None if hasattr(model, "NonlocalResult") else "NonlocalResult is missing"


@pytest.fixture(autouse=True)
def require_writeback() -> None:
    if MISSING is not None:
        pytest.fail(f"nonlocal write-back is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int, str | None]]:
    return sorted((f.rule_id, f.span.start_line, f.function) for f in findings)


def printed(text: str) -> str:
    return format_module(lower_module(build_hir(SourceManager().add_source("m.py", text))))


OUTSIDE = "import os\n\ndef outer():\n    cmd = 'ls'\n    def set_cmd():\n        nonlocal cmd\n        cmd = input()\n    set_cmd()\n    os.system(cmd)\n"


def test_the_call_rebinds_the_written_nonlocal_in_the_enclosing_function() -> None:
    outer = printed(OUTSIDE).split("func @outer.set_cmd")[0]

    assert "nonlocal_result" in outer
    assert outer.index("= call") < outer.index("nonlocal_result") < outer.index('store_local "cmd"', outer.index("= call"))


def test_a_nonlocal_write_flows_back_to_the_caller() -> None:
    assert rules(check(OUTSIDE)) == [("command-injection", 9, "outer")]


def test_a_nonlocal_write_from_a_parameter_flows_back() -> None:
    text = (
        "import os\n\ndef outer():\n    cmd = 'ls'\n    def set_cmd(value):\n        nonlocal cmd\n"
        "        cmd = value\n    set_cmd(input())\n    os.system(cmd)\n"
    )
    assert rules(check(text)) == [("command-injection", 9, "outer")]


def test_a_nonlocal_written_with_a_constant_does_not_taint_the_caller() -> None:
    text = (
        "import os\n\ndef outer():\n    cmd = input()\n    def reset():\n        nonlocal cmd\n"
        "        cmd = 'ls'\n    reset()\n    os.system(cmd)\n"
    )
    assert check(text) == ()


def test_unwritten_captures_and_other_locals_are_untouched() -> None:
    text = (
        "import os\n\ndef outer():\n    cmd = 'ls'\n    other = 'pwd'\n    def set_cmd():\n        nonlocal cmd\n"
        "        cmd = input()\n        os.system(other)\n    set_cmd()\n    os.system(other)\n"
    )
    assert check(text) == ()


def test_summaries_record_nonlocal_writes_and_survive_the_cache(tmp_path: Path) -> None:
    from coretrace_python.cache import ProjectCache

    (tmp_path / "m.py").write_text(OUTSIDE, encoding="utf-8")
    cache = ProjectCache(tmp_path / "cache")
    first = engine.analyze_project(tmp_path, [PLUGINS], cache=cache)
    second = engine.analyze_project(tmp_path, [PLUGINS], cache=cache)

    assert second.reused == ("m",)
    assert rules(second.findings) == rules(first.findings) == [("command-injection", 9, "outer")]
    entries = [json.loads(p.read_text(encoding="utf-8")) for p in (tmp_path / "cache").glob("*.json")]
    assert any("nonlocal_writes" in json.dumps(entry) for entry in entries)
    assert "nonlocal_writes" in FunctionSummary.__dataclass_fields__
