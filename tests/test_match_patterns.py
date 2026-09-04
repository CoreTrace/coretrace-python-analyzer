"""Acceptance tests for sequence, mapping and class patterns in ``match`` (option 2,
last point of the consolidation).

The CFG builder already lays a ``match`` out as an ``if`` chain over a hidden subject for
literal, capture, wildcard and or-patterns. Structural patterns join them: a sequence
pattern tests the length and applies its sub-patterns to indexed items, a star
capturing the middle slice; a mapping pattern tests each key's membership and applies
sub-patterns to the values; a class pattern tests ``isinstance`` and applies keyword
sub-patterns to attributes. Positional class patterns need ``__match_args__`` and stay
reported. Captures bind ordinary locals, so taint flows through them.

Expected to remain red until ``SequencePattern``, ``MappingPattern``, ``ClassPattern``
and their layout exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.source import SourceManager

try:
    from coretrace_python.hir.nodes import (
        ClassPattern,
        MappingPattern,
        SequencePattern,
        StarPattern,
    )
except ImportError as error:  # pragma: no cover - red until the patterns land
    MISSING: Exception | None = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_patterns() -> None:
    if MISSING is not None:
        pytest.fail(f"structural match patterns are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("m.py", text))


def printed(text: str) -> str:
    return format_module(lower_module(hir(text)))


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int]]:
    return sorted((f.rule_id, f.span.start_line) for f in findings)


def notes(text: str) -> list[str]:
    return [f.message for f in check(text) if f.rule_id in ("syntax-error", "unsupported-syntax")]


# --------------------------------------------------------------------------- HIR


def test_structural_patterns_are_represented() -> None:
    module = hir(
        "def f(p):\n"
        "    match p:\n"
        "        case [x, 0, *rest]:\n            return x\n"
        "        case {'op': op, **extra}:\n            return op\n"
        "        case Point(x=0, y=y):\n            return y\n"
    )
    statement = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(statement, nodes.Match)
    sequence, mapping, klass = (case.pattern for case in statement.cases)

    assert isinstance(sequence, SequencePattern)
    assert [type(p).__name__ for p in sequence.patterns] == ["CapturePattern", "ValuePattern", "StarPattern"]
    assert isinstance(sequence.patterns[2], StarPattern) and sequence.patterns[2].name == "rest"
    assert isinstance(mapping, MappingPattern) and mapping.rest == "extra"
    assert [k.value for k in mapping.keys if isinstance(k, nodes.Constant)] == ["op"]
    assert isinstance(klass, ClassPattern)
    assert isinstance(klass.cls, nodes.Name) and klass.cls.identifier == "Point"
    assert klass.keyword_names == ("x", "y") and len(klass.keyword_patterns) == 2 and klass.patterns == ()


def test_captures_inside_structural_patterns_are_locals() -> None:
    from coretrace_python.semantic.scopes import BindingKind, analyze_scopes

    module = hir("def f(p):\n    match p:\n        case [x, *rest]:\n            return x, rest\n        case {'k': v}:\n            return v\n        case P(a=a):\n            return a\n")
    scopes = analyze_scopes(module)
    f = next(s for s in scopes.children(scopes.module_scope.id) if s.name == "f")

    assert all(f.bindings[name].kind is BindingKind.LOCAL for name in ("x", "rest", "v", "a"))


# --------------------------------------------------------------------------- layout


def test_sequence_patterns_test_the_length_and_index_the_items() -> None:
    text = printed("def f(p):\n    match p:\n        case [a, 'b']:\n            return a\n        case [first, *rest]:\n            return rest\n        case _:\n            return None\n")

    assert "python.builtins.len" in text
    assert "compare.eq" in text and "compare.gt_eq" in text
    assert "build_slice" in text
    assert notes("def f(p):\n    match p:\n        case [a, 'b']:\n            return a\n") == []


def test_mapping_and_class_patterns_lower_to_membership_and_isinstance() -> None:
    text = printed(
        "def f(p):\n    match p:\n        case {'op': op, 'n': 1}:\n            return op\n"
        "        case Point(x=0, y=y):\n            return y\n"
    )
    assert "compare.in" in text
    assert "python.builtins.isinstance" in text
    assert notes("def f(p):\n    match p:\n        case {'op': op}:\n            return op\n        case Point(y=y):\n            return y\n") == []


def test_positional_class_patterns_on_unknown_classes_lower_conservatively() -> None:
    assert notes("def f(p):\n    match p:\n        case Point(0, y):\n            return y\n") == []


# --------------------------------------------------------------------------- taint


def test_taint_flows_through_captures_of_every_pattern_kind() -> None:
    assert rules(
        check("import os\n\ndef f():\n    match input().split():\n        case [cmd, *args]:\n            os.system(cmd)\n            os.system(args[0])\n")
    ) == [("command-injection", 6), ("command-injection", 7)]
    assert rules(
        check("import os\nimport json\n\ndef f():\n    match json.loads(input()):\n        case {'cmd': cmd, **rest}:\n            os.system(cmd)\n            os.system(rest['x'])\n")
    ) == [("command-injection", 7), ("command-injection", 8)]
    assert rules(
        check("import os\n\ndef f(req):\n    match req:\n        case Request(body=body) if body:\n            os.system(input() + body)\n")
    ) == [("command-injection", 6)]


def test_guards_see_the_captures() -> None:
    assert rules(
        check("import os\n\ndef f():\n    match input().split():\n        case [cmd, count] if count.isdigit():\n            os.system(cmd)\n")
    ) == [("command-injection", 6)]
    assert check("import os\n\ndef f():\n    match input().split():\n        case [cmd] if cmd.isdigit():\n            os.system(cmd)\n") == ()
