"""Acceptance tests for the syntax gaps found on large projects (issue #71).

Assignment expressions (``(y := f(x))``), ``yield from`` and starred assignment targets
(``first, *rest = items``) used to reject the whole file as a ``syntax-error``. They are
now part of the supported subset: a walrus is laid out by the CFG builder as an
assignment before the statement that reads it, recomputed every iteration in a ``while``
condition; ``yield from`` is a delegating yield; a starred target receives the slice of
the unpacked value that the other targets leave.

Expected to remain red until the HIR has ``NamedExpr`` and the adapter accepts the three forms.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.source import SourceManager

MISSING = None if hasattr(nodes, "NamedExpr") else "nodes.NamedExpr is missing"


@pytest.fixture(autouse=True)
def require_gaps() -> None:
    if MISSING is not None:
        pytest.fail(f"the frontend gaps are not closed yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("m.py", text))


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


# --------------------------------------------------------------------------- HIR


def test_the_three_forms_build_a_hir() -> None:
    module = hir("def f(items, g):\n    first, *rest = items\n    total = yield from g()\n    if (n := len(rest)):\n        return n\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    unpack, delegate, branch = function.body

    assert isinstance(unpack, nodes.Assign) and isinstance(unpack.target, nodes.Tuple)
    assert isinstance(unpack.target.elements[1], nodes.Starred)
    assert isinstance(unpack.target.elements[1].value, nodes.Name)
    assert isinstance(delegate, nodes.Assign) and isinstance(delegate.value, nodes.Yield)
    assert delegate.value.delegate is True
    assert isinstance(branch, nodes.If) and isinstance(branch.condition, nodes.NamedExpr)
    assert branch.condition.target.identifier == "n"


# --------------------------------------------------------------------------- analysis


def test_walrus_in_a_condition_is_analysed_and_carries_taint() -> None:
    findings = check("import os\n\ndef run():\n    if (cmd := input()):\n        os.system(cmd)\n")

    assert rules(findings) == ["command-injection"]


def test_walrus_in_a_while_condition_is_recomputed_each_iteration() -> None:
    findings = check("import os\n\ndef run():\n    while (line := input()):\n        os.system(line)\n")

    assert rules(findings) == ["command-injection"]


def test_walrus_inside_a_comprehension_binds_in_the_function() -> None:
    findings = check("import os\n\ndef run(xs):\n    ys = [y for x in xs if (y := input())]\n    os.system(y)\n")

    assert rules(findings) == ["command-injection"]


def test_yield_from_is_a_delegating_yield() -> None:
    findings = check("import os\n\ndef run(gen):\n    data = yield from gen\n    os.system(input())\n")

    assert rules(findings) == ["command-injection"]


def test_starred_targets_receive_the_remaining_elements() -> None:
    findings = check(
        "import os\n\ndef run():\n    first, *rest, last = [input(), 'x', 'y']\n    os.system(rest[0])\n    os.system(first)\n"
    )

    assert rules(findings) == ["command-injection", "command-injection"]


def test_the_forms_leave_coverage_complete() -> None:
    analysis = engine.analyze_file(
        SourceManager().add_source(
            "m.py", "def a(items):\n    x, *y = items\n\ndef b(g):\n    yield from g\n\ndef c(v):\n    return (w := v)\n"
        ),
        [PLUGINS],
    )

    assert analysis.coverage.summary() == "coverage: 1/1 files, 3/3 functions"
    assert analysis.findings == ()
