"""Acceptance tests for class keyword arguments and general ``with`` targets (issue #71).

``class Task(Base, metaclass=Register)`` and ``with ctx() as self.conn`` or
``as (a, b)`` rejected the whole file as a ``syntax-error`` on the broadened corpus (12
files in luigi, 2 in httpie, 1 in the FastAPI template). Class keyword arguments are kept
on the class and evaluated where the class is defined; a ``with`` target is any assignable
target and receives what the context manager enters.

Expected to remain red until ``nodes.Class`` has ``keywords`` and ``WithItem.target`` is a target.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.source import SourceManager

MISSING = None if "keywords" in nodes.Class.__dataclass_fields__ else "Class has no keywords"


@pytest.fixture(autouse=True)
def require_forms() -> None:
    if MISSING is not None:
        pytest.fail(f"the forms are not supported yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("m.py", text))


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


def test_class_keyword_arguments_are_kept_on_the_class() -> None:
    module = hir("class Task(Base, metaclass=Register, flag=True):\n    pass\n")
    cls = module.body[0]

    assert isinstance(cls, nodes.Class)
    assert [k.name for k in cls.keywords] == ["metaclass", "flag"]
    assert isinstance(cls.keywords[0].value, nodes.Name) and cls.keywords[0].value.identifier == "Register"


def test_with_targets_may_be_attributes_subscripts_and_tuples() -> None:
    module = hir("def f(self, d):\n    with a() as self.conn, b() as d['k'], c() as (x, y):\n        pass\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    statement = function.body[0]
    assert isinstance(statement, nodes.With)
    targets = [item.target for item in statement.items]

    assert isinstance(targets[0], nodes.Attribute)
    assert isinstance(targets[1], nodes.Subscript)
    assert isinstance(targets[2], nodes.Tuple)


def test_methods_of_a_class_with_keyword_arguments_are_analysed() -> None:
    text = "import os\n\nclass Task(object, metaclass=type):\n    def run(self):\n        os.system(input())\n"
    analysis = engine.analyze_file(SourceManager().add_source("m.py", text), [PLUGINS])

    assert rules(analysis.findings) == ["command-injection"]
    assert analysis.coverage.summary() == "coverage: 1/1 files, 1/1 functions"


def test_a_local_class_with_keyword_arguments_evaluates_them() -> None:
    text = "import os\n\ndef make(meta):\n    class Task(metaclass=meta):\n        def run(self):\n            os.system(input())\n    return Task\n"
    analysis = engine.analyze_file(SourceManager().add_source("m.py", text), [PLUGINS])

    assert rules(analysis.findings) == ["command-injection"]
    assert analysis.coverage.summary() == "coverage: 1/1 files, 2/2 functions"


def test_with_targets_receive_the_entered_value() -> None:
    text = "import os\n\ndef run(ctx):\n    with ctx(input()) as (cmd, other):\n        os.system(cmd)\n"
    assert rules(check(text)) == ["command-injection"]
    text = "import os\n\nclass R:\n    def run(self, ctx):\n        with ctx(input()) as self.cmd:\n            os.system(self.cmd)\n"
    assert rules(check(text)) == ["command-injection"]
