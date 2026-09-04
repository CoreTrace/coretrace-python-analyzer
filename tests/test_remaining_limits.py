"""Acceptance tests for the four documented limits Hugo asked to close.

- Positional class patterns: ``case Point(0, y)`` uses the class's ``__match_args__``
  when the class is defined in the module, explicitly or as a dataclass field order; for
  an unknown class each position is a conservative attribute of the subject, so the
  match lowers and taint still flows.
- ``nonlocal``: the declared name becomes a local of the nested function initialised
  from the captured value, so the body is analysed; the write does not flow back to the
  enclosing function yet, which is documented.
- A class defined inside a function is a ``MakeClass`` value bound to its name; its
  methods are analysed as nested functions.
- Control flow inside a ``while`` condition: the loop becomes ``while True`` with the
  condition recomputed at the top of the body and a ``break``, the ``else`` clause
  running before that ``break``.

Expected to remain red until these four lower.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import analyzable_functions, lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.source import SourceManager

try:
    from coretrace_python.ir.model import MakeClass
except ImportError as error:  # pragma: no cover - red until the limits close
    MISSING: Exception | None = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_limits() -> None:
    if MISSING is not None:
        pytest.fail(f"the remaining limits are not closed yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("m.py", text))


def printed(text: str) -> str:
    return format_module(lower_module(hir(text)))


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int, str | None]]:
    return sorted((f.rule_id, f.span.start_line, f.function) for f in findings)


def notes(text: str) -> list[str]:
    return [f.message for f in check(text) if f.rule_id in ("syntax-error", "unsupported-syntax")]


# --------------------------------------------------------------------------- positional class patterns


POINT = "class Point:\n    __match_args__ = ('x', 'y')\n\n    def __init__(self, x, y):\n        self.x = x\n        self.y = y\n\n"


def test_positional_class_patterns_use_match_args() -> None:
    text = printed(POINT + "def f(p):\n    match p:\n        case Point(0, y):\n            return y\n    return None\n")

    assert "get_attr %" in text and "'x'" in text and "'y'" in text
    assert "python.builtins.isinstance" in text
    assert notes(POINT + "def f(p):\n    match p:\n        case Point(0, y):\n            return y\n") == []


def test_dataclass_fields_order_the_positions() -> None:
    text = printed(
        "from dataclasses import dataclass\n\n@dataclass\nclass Pair:\n    left: int\n    right: int = 0\n\n"
        "def f(p):\n    match p:\n        case Pair(1, r):\n            return r\n    return None\n"
    )
    assert "'left'" in text and "'right'" in text


def test_unknown_classes_match_positions_conservatively() -> None:
    assert notes("def f(p):\n    match p:\n        case Vec(0, y):\n            return y\n") == []
    text = printed("def f(p):\n    match p:\n        case Vec(0, y):\n            return y\n    return None\n")
    assert "'_match_arg_0'" in text and "'_match_arg_1'" in text


def test_taint_flows_through_positional_captures() -> None:
    findings = check(
        "import os\n\n" + POINT + "def f():\n    p = Point(input(), 1)\n    match p:\n        case Point(cmd, _):\n            os.system(cmd)\n"
    )
    assert rules(findings) == [("command-injection", 14, "f")]


# --------------------------------------------------------------------------- nonlocal


def test_nonlocal_assignments_lower_as_locals_of_the_nested_function() -> None:
    text = "def outer():\n    n = 0\n    def bump():\n        nonlocal n\n        n = n + 1\n        return n\n    bump()\n    return n\n"
    assert notes(text) == []
    lowered = printed(text)
    assert 'store_local "n"' in lowered.split("func @outer.bump")[1]


def test_a_nonlocal_write_is_visible_inside_the_writer_but_not_yet_outside() -> None:
    inside = "import os\n\ndef outer():\n    cmd = 'ls'\n    def set_cmd():\n        nonlocal cmd\n        cmd = input()\n        os.system(cmd)\n    set_cmd()\n"
    assert rules(check(inside)) == [("command-injection", 8, "set_cmd")]
    # Documented limit: the write does not flow back to the enclosing function.
    outside = "import os\n\ndef outer():\n    cmd = 'ls'\n    def set_cmd():\n        nonlocal cmd\n        cmd = input()\n    set_cmd()\n    os.system(cmd)\n"
    assert check(outside) == ()


# --------------------------------------------------------------------------- classes inside functions


def test_classes_defined_inside_functions_are_values_with_analysed_methods() -> None:
    text = "import os\n\ndef outer():\n    class Inner:\n        def run(self):\n            os.system(input())\n    return Inner\n"
    assert notes(text) == []
    lowered = printed(text)
    assert 'make_class "Inner"' in lowered and 'store_local "Inner"' in lowered
    assert "func @outer.Inner.run" in lowered
    assert [f.name for f in analyzable_functions(hir(text))] == ["outer", "run"]
    assert rules(check(text)) == [("command-injection", 6, "run")]
    (made,) = [i for f in lower_module(hir(text)).functions for b in f.blocks for i in b.instructions if isinstance(i, MakeClass)]
    assert made.name == "Inner"


def test_local_class_bases_and_decorators_are_evaluated() -> None:
    text = "def outer(base, deco):\n    @deco\n    class Inner(base):\n        pass\n    return Inner\n"
    assert notes(text) == []
    assert "make_class" in printed(text)


# --------------------------------------------------------------------------- control flow in while conditions


def test_conditionals_and_comprehensions_in_while_conditions_lower() -> None:
    text = "def f(flag, items):\n    n = 0\n    while (items if flag else []) and [i for i in items if i]:\n        n = n + 1\n        items = items[1:]\n    return n\n"
    assert notes(text) == []
    lowered = printed(text)
    assert lowered.count("for_next") >= 1 and "branch" in lowered


def test_the_condition_is_recomputed_every_iteration_and_else_still_runs() -> None:
    text = (
        "import os\n\n"
        "def f(flag):\n"
        "    while (input() if flag else 'q') != 'q':\n"
        "        os.system('echo')\n"
        "    else:\n"
        "        return 'done'\n"
        "    return 'broken'\n"
    )
    assert notes(text) == []
    lowered = printed(text)
    assert "'done'" in lowered and "'broken'" in lowered
    assert "python.builtins.input" in lowered.split("loop_1:")[1]
