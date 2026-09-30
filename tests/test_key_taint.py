"""The keys of a mapping carry taint of their own (issue #193).

A dict literal ``{taint: value}``, ``dict([(taint, value)])``, a comprehension ``{k: v for
k in taint}`` and a subscript assignment ``mapping[taint] = value`` taint the ``keys``
field of the mapping's abstract object, apart from its ``elements`` and from the value
taint the mapping keeps as before; ``{**d}``, ``dict(d)`` and ``dict(**d)`` copy it. A
call expanding such a mapping with ``**`` passes its keys as the keyword names of the
call, the ``(None, "**")`` way of the flow, which only an advisory sink reads. Call sites
record whether every keyword name is written (``Arguments.keyword_unpacked``): a ``**``
literal with constant keys that nothing else touches is recorded as its keywords.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.abstract import ELEMENTS, HeapAnalysis
from coretrace_python.abstract.heap import AbstractObject, HeapLocation
from coretrace_python.analysis import AnalysisManager
from coretrace_python.cache import CachedModule, ProjectCache
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import Arguments, CallGraphAnalysis, CallSite, ExternalSymbol
from coretrace_python.ir.model import Return
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceId, SourceManager, SourceSpan
from coretrace_python.taint import (
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintAnalysis,
    TaintFacts,
    TaintFlow,
    TaintKind,
)

try:
    from coretrace_python.abstract import KEYS
    from coretrace_python.taint import KEYWORD_NAMES
except ImportError as error:  # pragma: no cover - red until key taint lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_key_taint() -> None:
    if MISSING is not None:
        pytest.fail(f"key taint is not implemented yet: {MISSING}")


MODELS = (
    Source(SymbolId("python.builtins.input"), "stdin"),
    Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
    Sink(SymbolId("python.vulnlib.sink"), TaintKind.ADVISORY),
)
PRELUDE = "import os\nimport vulnlib\n\n"


def manager_for(body: str) -> AnalysisManager:
    module = build_hir(SourceManager().add_source("m.py", PRELUDE + body))
    manager = AnalysisManager(module)
    manager.register(*engine.ALL_ANALYSES)
    registry = SecurityModelRegistry()
    registry.register(*MODELS)
    manager.provide(SecurityModelAnalysis, registry.freeze())
    return manager


def function_named(manager: AnalysisManager, name: str) -> nodes.Function:
    return next(s for s in manager.module.body if isinstance(s, nodes.Function) and s.name == name)


def returned_mapping(body: str) -> tuple[TaintFacts, frozenset[AbstractObject]]:
    """The taint facts of ``f`` and the objects of the mapping it returns."""

    manager = manager_for(body)
    function = function_named(manager, "f")
    ssa = manager.get(SSAAnalysis, function)
    returned = next(b.terminator.value for b in ssa.blocks if isinstance(b.terminator, Return))
    assert returned is not None
    objects = manager.get(HeapAnalysis, function).objects(returned)
    assert objects
    return manager.get(TaintAnalysis, function), objects


def flows_of(body: str) -> tuple[TaintFlow, ...]:
    manager = manager_for(body)
    return manager.get(TaintAnalysis, function_named(manager, "f")).flows


def arguments_of(call: str, before: str = "") -> Arguments:
    manager = manager_for(f"def run(m, xs, k):\n{before}    {call}\n")
    graph = manager.get(CallGraphAnalysis)
    site = next(s for s in graph.sites("run") if s.target == ExternalSymbol(SymbolId("python.vulnlib.f")))
    return site.arguments


# --------------------------------------------------------------------------- key taint


@pytest.mark.parametrize(
    "body",
    [
        "def f():\n    d = {input(): 1}\n    return d\n",
        "def f():\n    d = dict([(input(), 1)])\n    return d\n",
        "def f():\n    d = {k: 1 for k in input()}\n    return d\n",
        "def f():\n    d = {}\n    d[input()] = 1\n    return d\n",
        "def f():\n    m = {input(): 1}\n    d = {**m}\n    return d\n",
        "def f():\n    m = {input(): 1}\n    d = dict(m)\n    return d\n",
        "def f():\n    m = {input(): 1}\n    d = dict(**m)\n    return d\n",
    ],
    ids=["literal", "pairs", "comprehension", "subscript-assignment", "unpacked", "dict-copy", "dict-expanded"],
)
def test_attacker_keys_taint_the_keys_of_the_mapping_and_not_its_elements(body: str) -> None:
    facts, objects = returned_mapping(body)

    assert all(facts.heap(HeapLocation(o, KEYS)).kinds == TaintKind.ALL for o in objects)
    assert not any(facts.heap(HeapLocation(o, ELEMENTS)) for o in objects)


def test_attacker_values_leave_the_keys_clean() -> None:
    facts, objects = returned_mapping("def f():\n    d = {'k': input()}\n    return d\n")

    assert not any(facts.heap(HeapLocation(o, KEYS)) for o in objects)


def test_a_subscript_assignment_taints_the_keys_apart_from_the_mapping_itself() -> None:
    body = "def f():\n    d = {}\n    d[input()] = 1\n    return d\n"
    manager = manager_for(body)
    function = function_named(manager, "f")
    ssa = manager.get(SSAAnalysis, function)
    returned = next(b.terminator.value for b in ssa.blocks if isinstance(b.terminator, Return))
    assert returned is not None
    (obj,) = manager.get(HeapAnalysis, function).objects(returned)

    facts = manager.get(TaintAnalysis, function)

    assert facts.heap(HeapLocation(obj, KEYS)).kinds == TaintKind.ALL
    assert not facts.heap(HeapLocation(obj, ELEMENTS))
    assert not facts.taint(returned)


# --------------------------------------------------------------------------- flows


def test_the_keyword_names_way_is_the_double_star() -> None:
    assert KEYWORD_NAMES == "**"


@pytest.mark.parametrize(
    "body, ways",
    [
        ("def f():\n    d = {input(): 1}\n    vulnlib.sink(**d)\n", {(None, None), (None, "**")}),
        ("def f():\n    d = {}\n    d[input()] = 1\n    vulnlib.sink(**d)\n", {(None, "**")}),
        ("def f():\n    d = {'k': input()}\n    vulnlib.sink(**d)\n", {(None, None)}),
    ],
    ids=["tainted-key-literal", "tainted-keys-only", "tainted-value"],
)
def test_keys_expanded_into_an_advisory_sink_are_passed_as_its_keyword_names(
    body: str, ways: set[tuple[int | None, str | None]]
) -> None:
    (flow,) = flows_of(body)

    assert flow.kinds == TaintKind.ADVISORY
    assert flow.passed_as == frozenset(ways)


def test_no_other_sink_reads_the_keyword_names() -> None:
    assert flows_of("def f():\n    d = {}\n    d[input()] = 1\n    os.system(**d)\n") == ()


# --------------------------------------------------------------------------- call sites


@pytest.mark.parametrize(
    "call, before, expected",
    [
        ('vulnlib.f(**{"a": 1})', "", ((), (("a", "1"),), False, False)),
        ('vulnlib.f(1, **{"a": 1})', "", (("1",), (("a", "1"),), False, False)),
        ("vulnlib.f(**m)", "", ((), (), True, True)),
        ("vulnlib.f(*xs)", "", ((), (), True, False)),
        ('vulnlib.f(*xs, **{"a": 1})', "", ((), (("a", "1"),), True, False)),
        ('vulnlib.f(**dict(a=1, **{"b": 2}))', "", ((), (("a", "1"), ("b", "2")), False, False)),
        ("vulnlib.f(**{k: 1})", "", ((), (), True, True)),
        ("vulnlib.f(**dict(m))", "", ((), (), True, True)),
        ("vulnlib.f(**opts)", '    opts = {"a": 1}\n', ((), (("a", "1"),), False, False)),
        # A literal filled after its construction has keys the literal does not write.
        ("vulnlib.f(**opts)", '    opts = {"a": 1}\n    opts[k] = 2\n', ((), (), True, True)),
        ("vulnlib.f(**opts)", "    opts = {}\n    opts[k] = 1\n", ((), (), True, True)),
    ],
    ids=[
        "literal",
        "literal-after-positional",
        "parameter",
        "starred",
        "starred-and-literal",
        "dict-with-nested-literal",
        "computed-key",
        "dict-copy",
        "literal-by-name",
        "literal-then-assigned",
        "empty-literal-then-assigned",
    ],
)
def test_call_sites_record_whether_every_keyword_name_is_written(
    call: str, before: str, expected: tuple[object, ...]
) -> None:
    found = arguments_of(call, before)

    assert (found.positional, found.keywords, found.unpacked, found.keyword_unpacked) == expected


def test_keyword_unpacked_round_trips_through_the_cache(tmp_path: Path) -> None:
    span = SourceSpan(SourceId("/p/a.py"), 3, 5, 3, 9)
    site = CallSite("f", span, ExternalSymbol(SymbolId("python.vulnlib.f")), Arguments((), (), True, True))
    cache = ProjectCache(tmp_path / "cache")

    cache.store("key", CachedModule((), {}, (site,), ()))
    restored = cache.load("key")

    assert restored is not None
    assert restored.sites == (site,)
    assert restored.sites[0].arguments.keyword_unpacked is True
