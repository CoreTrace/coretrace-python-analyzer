"""Acceptance tests for issue #261: the summary fixpoint of a module terminates.

A function's summary lists the external calls it reaches, its own and those of the
project functions it calls. Those of a callee used to be copied in the callee's order, so
around a cycle of three functions or more each function's order depended on the order
its callee had in the previous round: the content settled, the order rotated, and the
order-sensitive comparison that ends the fixpoint never held. The analysis then never
returned. A summary now lists its external calls in source order, whatever the order in
which the rounds met them.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cfg import CFGAnalysis
from coretrace_python.frontend import build_hir
from coretrace_python.interprocedural import CallGraphAnalysis, SummaryAnalysis
from coretrace_python.interprocedural.summaries import summarize
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.source import SourceManager

# A converging analysis of these files takes about a second: a run past this is one that
# would not end.
TIMEOUT = 60

THREE_FUNCTIONS = """\
import os


def a(x):
    b(x)
    os.system(x)


def b(x):
    c(x)
    print(x)


def c(x):
    a(x)


def run():
    a(input())
"""

FOUR_FUNCTIONS = """\
import os


def a(x):
    b(x)
    os.system(x)


def b(x):
    c(x)
    print(x)


def c(x):
    d(x)


def d(x):
    a(x)


def run():
    a(input())
"""

# The shape of ansible's ``Role.load``, ``_load_role_data`` and ``_load_dependencies``.
EXCEPTION_HANDLERS = """\
import os


def load(include):
    try:
        load_data(include)
    except RuntimeError:
        raise ValueError(include.ds)


def load_data(include):
    load_dependencies(include)
    try:
        os.system(include)
    except AssertionError:
        raise ValueError(include.name)


def load_dependencies(include):
    load(include)


def run():
    load(input())
"""


def checked(tmp_path: Path, source: str) -> list[tuple[str, int, str | None]]:
    """The findings of ``--check`` on a project of one module, failing the test instead of
    waiting when the analysis does not end."""

    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text(source, encoding="utf-8")
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "coretrace_python", "--check", str(root), "--format", "json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the analysis did not end within {TIMEOUT} s")
    report = json.loads(completed.stdout)
    return [(f["rule_id"], f["location"]["line"], f["metadata"].get("verdict")) for f in report["findings"]]


@pytest.mark.parametrize(
    ("source", "line"),
    [(THREE_FUNCTIONS, 19), (FOUR_FUNCTIONS, 23), (EXCEPTION_HANDLERS, 24)],
    ids=["three-functions", "four-functions", "exception-handlers"],
)
def test_a_call_cycle_with_external_calls_after_the_recursive_call_is_checked(
    tmp_path: Path, source: str, line: int
) -> None:
    assert checked(tmp_path, source) == [("command-injection", line, "vulnerability")]


CALLEE_FIRST = """\
import os


def run(cmd):
    helper(cmd)
    os.system(cmd)


def helper(cmd):
    print(cmd)
    os.remove(cmd)
"""


def test_a_summary_lists_its_external_calls_in_source_order() -> None:
    # ``run`` meets ``helper``'s calls first, at line 5, then its own at line 6.
    table = engine.build_manager(build_hir(SourceManager().add_source("app.py", CALLEE_FIRST))).get(SummaryAnalysis)

    assert [(str(c.symbol), c.location.start_line) for c in table.summary("run").external_calls] == [
        ("python.os.system", 6),
        ("python.builtins.print", 10),
        ("python.os.remove", 11),
    ]


def test_a_summary_does_not_depend_on_the_order_of_its_callee_s_external_calls() -> None:
    manager = engine.build_manager(build_hir(SourceManager().add_source("app.py", CALLEE_FIRST)))
    graph = manager.get(CallGraphAnalysis)
    summaries = manager.get(SummaryAnalysis)
    table = {name: summaries.summary(name) for name in summaries.names}
    helper = table["helper"]
    reversed_helper = dataclasses.replace(helper, external_calls=helper.external_calls[::-1])
    run = graph.definitions["run"]

    def run_summary(callee):
        return summarize(
            "run", manager.get(SSAAnalysis, run), manager.get(CFGAnalysis, run), graph, {**table, "helper": callee}
        )

    assert helper.external_calls != reversed_helper.external_calls
    assert run_summary(reversed_helper) == run_summary(helper)
