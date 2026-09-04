"""Acceptance tests for the heap and aliasing abstraction (``docs/architecture.md`` §22,
§19; roadmap issue #35).

SSA names values, not objects: ``b = a; b.append(x); sink(a[0])`` is invisible to a
value-only taint. The coarse abstraction of §22 adds one ``AbstractObject`` per
allocation site (containers, calls, parameters, globals, loaded fields), an ``AliasSet``
of objects per value computed by a flow-insensitive points-to fixpoint, and two
``HeapLocation`` fields per object, ``elements`` and ``attributes``. Taint and
dependence flow through stores, mutating method calls and loads on those locations, and
function summaries record the parameters a function mutates and the module globals it
touches, so mutations cross calls and files.

Expected to remain red until ``abstract.heap``, heap-aware taint and summaries with
``mutations`` and ``side_effects`` exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import FunctionSummary, SummaryAnalysis
from coretrace_python.ir.model import (
    BuildList,
    FunctionIR,
    GetAttr,
    GetItem,
    Instruction,
    Phi,
    Value,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import (
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintAnalysis,
    TaintKind,
)

try:
    from coretrace_python.abstract import HeapAnalysis, HeapFacts
    from coretrace_python.abstract.heap import AllocationSite, HeapLocation
    from coretrace_python.interprocedural import Mutation
except ImportError as error:  # pragma: no cover - red until the heap lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_heap() -> None:
    if MISSING is not None:
        pytest.fail(f"heap abstraction is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

MODELS = (
    Source(SymbolId("python.builtins.input"), "stdin"),
    Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
)
PRELUDE = "import os\nfrom config import Config\n\n"


def manager_for(body: str, prelude: str = PRELUDE) -> AnalysisManager:
    module = build_hir(SourceManager().add_source("m.py", prelude + body))
    manager = AnalysisManager(module)
    manager.register(*engine.ALL_ANALYSES)
    registry = SecurityModelRegistry()
    registry.register(*MODELS)
    manager.provide(SecurityModelAnalysis, registry.freeze())
    return manager


def function_named(manager: AnalysisManager, name: str) -> nodes.Function:
    return next(s for s in manager.module.body if isinstance(s, nodes.Function) and s.name == name)


def heap_of(body: str, name: str = "f") -> tuple[FunctionIR, HeapFacts]:
    manager = manager_for(body)
    function = function_named(manager, name)
    return manager.get(SSAAnalysis, function), manager.get(HeapAnalysis, function)


def instructions(ssa: FunctionIR, kind: type[Instruction]) -> list[Instruction]:
    return [i for block in ssa.blocks for i in block.instructions if isinstance(i, kind)]


def result_of(instruction: Instruction) -> Value:
    assert instruction.result is not None
    return instruction.result


def flow_lines(body: str, name: str = "f") -> list[int]:
    manager = manager_for(body)
    function = function_named(manager, name)
    return sorted(flow.location.start_line for flow in manager.get(TaintAnalysis, function).flows)


def summary_of(body: str, name: str) -> FunctionSummary:
    manager = manager_for(body, "import os\n\n")
    return manager.get(SummaryAnalysis).summary(name)


def check_lines(text: str) -> list[tuple[str, int]]:
    findings = engine.check(SourceManager().add_source("app.py", text), [PLUGINS])
    return sorted((f.rule_id, f.span.start_line) for f in findings)


# --------------------------------------------------------------------------- points-to


def test_containers_get_one_object_per_allocation_site() -> None:
    ssa, heap = heap_of("def f():\n    a = []\n    b = []\n    return a, b\n")
    first, second = instructions(ssa, BuildList)

    (object_a,) = heap.objects(result_of(first))
    (object_b,) = heap.objects(result_of(second))

    assert object_a != object_b
    assert object_a.site == AllocationSite("list", first.location)
    assert str(object_a.site) == "list@m.py:5"
    assert str(HeapLocation(object_a, "elements")) == "list@m.py:5.elements"
    assert HeapAnalysis.name == "abstract.heap"
    assert SSAAnalysis in HeapAnalysis.requires
    assert HeapAnalysis in engine.ALL_ANALYSES


def test_aliases_merge_through_phis_and_stay_separate_otherwise() -> None:
    ssa, heap = heap_of(
        "def f(c):\n    a = []\n    b = []\n    if c:\n        x = a\n    else:\n        x = b\n    return x, a\n"
    )
    lists = instructions(ssa, BuildList)
    (phi_value,) = instructions(ssa, Phi)

    objects = heap.objects(result_of(phi_value))

    assert objects == heap.objects(result_of(lists[0])) | heap.objects(result_of(lists[1]))
    assert len(objects) == 2


def test_parameters_and_globals_are_objects_of_their_own() -> None:
    ssa, heap = heap_of("cache = []\n\ndef f(items, other):\n    cache.append(items)\n    return other\n")

    (items,) = heap.objects(ssa.parameters[0])
    (other,) = heap.objects(ssa.parameters[1])

    assert items.site.kind == "parameter" and other.site.kind == "parameter"
    assert items != other
    assert any(o.site.kind == "global" and o.site.name == "cache" for value in heap.values for o in heap.objects(value))


def test_loaded_fields_are_deterministic_objects() -> None:
    ssa, heap = heap_of("def f():\n    cfg = Config()\n    first = cfg.cmd\n    second = cfg.cmd\n    return first, second\n")
    first, second = instructions(ssa, GetAttr)

    assert heap.objects(result_of(first)) == heap.objects(result_of(second))
    (field,) = heap.objects(result_of(first))
    assert field.site.kind == "field"


def test_stores_feed_later_loads() -> None:
    ssa, heap = heap_of("def f():\n    inner = []\n    box = {}\n    box['k'] = inner\n    out = box['k']\n    return out\n")
    (inner,) = instructions(ssa, BuildList)
    (load,) = instructions(ssa, GetItem)

    assert heap.objects(result_of(inner)) <= heap.objects(result_of(load))


def test_field_chains_in_loops_terminate() -> None:
    _, heap = heap_of("def f(node):\n    while node:\n        node = node.next\n    return node\n")
    assert heap is not None


# --------------------------------------------------------------------------- taint through the heap


def test_the_issue_example_is_a_flow() -> None:
    assert flow_lines("def f():\n    a = []\n    b = a\n    b.append(input())\n    os.system(a[0])\n") == [8]


@pytest.mark.parametrize(
    "body",
    [
        "def f():\n    d = {}\n    d['x'] = input()\n    os.system(d['x'])\n",
        "def f():\n    cfg = Config()\n    cfg.cmd = input()\n    os.system(cfg.cmd)\n",
        "def f():\n    a = []\n    a.extend([input()])\n    os.system(a[0])\n",
        "def f():\n    a = []\n    a.insert(0, input())\n    os.system(a[-1])\n",
        "def f():\n    s = set()\n    s.add(input())\n    os.system(list(s)[0])\n",
        "def f():\n    d = {}\n    d.update(x=input())\n    os.system(d['x'])\n",
        "def f():\n    a = []\n    a.append(input())\n    for item in a:\n        os.system(item)\n",
        "def f():\n    a = []\n    a.append(input())\n    os.system(' '.join(a))\n",
        "def f(c):\n    a = []\n    b = []\n    if c:\n        x = a\n    else:\n        x = b\n    x.append(input())\n    os.system(a[0])\n",
    ],
)
def test_stores_mutators_and_loads_carry_taint(body: str) -> None:
    assert len(flow_lines(body)) == 1


@pytest.mark.parametrize(
    "body",
    [
        "def f():\n    a = []\n    b = []\n    a.append(input())\n    os.system(b[0])\n",
        "def f():\n    a = []\n    a.append('ls')\n    os.system(a[0])\n",
        "def f():\n    cfg = Config()\n    other = Config()\n    cfg.cmd = input()\n    os.system(other.cmd)\n",
    ],
)
def test_unrelated_objects_and_clean_stores_stay_clean(body: str) -> None:
    assert flow_lines(body) == []


def test_heap_taint_is_exposed_by_location() -> None:
    manager = manager_for("def f():\n    a = []\n    a.append(input())\n    return a\n")
    function = function_named(manager, "f")
    ssa = manager.get(SSAAnalysis, function)
    heap = manager.get(HeapAnalysis, function)
    (allocation,) = instructions(ssa, BuildList)
    (obj,) = heap.objects(result_of(allocation))

    facts = manager.get(TaintAnalysis, function)

    assert facts.heap(HeapLocation(obj, "elements")).kinds == TaintKind.ALL
    assert not facts.heap(HeapLocation(obj, "attributes"))
    assert facts.taint(result_of(allocation)).kinds == TaintKind.NONE


# --------------------------------------------------------------------------- summaries


def test_summaries_record_parameter_mutations() -> None:
    summary = summary_of("def fill(items, value):\n    items.append(value)\n", "fill")

    assert summary.mutations == (Mutation(0, "elements", frozenset({1}), frozenset()),)
    assert summary.side_effects == frozenset()


def test_summaries_record_sources_stored_into_parameters_and_attribute_stores() -> None:
    fill = summary_of("def fill(items):\n    items.append(input())\n", "fill")
    configure = summary_of("def configure(cfg, cmd):\n    cfg.command = cmd\n", "configure")

    assert fill.mutations == (Mutation(0, "elements", frozenset(), frozenset({SymbolId("python.builtins.input")})),)
    assert configure.mutations == (Mutation(0, "attributes", frozenset({1}), frozenset()),)


def test_summaries_record_side_effects_on_module_globals() -> None:
    summary = summary_of("cache = []\n\ndef touch(x):\n    cache.append(x)\n", "touch")

    assert summary.side_effects == frozenset({"cache"})
    assert summary.mutations == ()


def test_pure_functions_have_no_mutations() -> None:
    summary = summary_of("def add(a, b):\n    return a + b\n", "add")
    assert summary.mutations == () and summary.side_effects == frozenset()


def test_mutations_compose_through_callers() -> None:
    summary = summary_of(
        "def fill(items, value):\n    items.append(value)\n\ndef wrap(xs, v):\n    fill(xs, v)\n",
        "wrap",
    )
    assert summary.mutations == (Mutation(0, "elements", frozenset({1}), frozenset()),)


def test_mutations_round_trip_through_the_cache_codec() -> None:
    from coretrace_python.cache import CachedModule, decode, encode

    summary = summary_of("def fill(items):\n    items.append(input())\n", "fill")

    restored = decode(json.loads(json.dumps(encode(CachedModule(("fill",), {"fill": summary}, (), ())))))

    assert restored.summaries["fill"] == summary


# --------------------------------------------------------------------------- interprocedural


def test_taint_flows_through_a_callee_that_mutates_its_argument() -> None:
    body = (
        "def fill(items, value):\n    items.append(value)\n\n"
        "def run():\n    a = []\n    fill(a, input())\n    os.system(a[0])\n"
    )
    assert flow_lines(body, "run") == [10]


def test_taint_flows_from_a_source_stored_by_the_callee() -> None:
    body = "def fill(items):\n    items.append(input())\n\ndef run():\n    a = []\n    fill(a)\n    os.system(a[0])\n"
    assert flow_lines(body, "run") == [10]


def test_callees_that_do_not_mutate_leave_arguments_clean() -> None:
    body = "def peek(items, value):\n    return len(items)\n\ndef run():\n    a = []\n    peek(a, input())\n    os.system(a[0])\n"
    assert flow_lines(body, "run") == []


def test_mutations_cross_files_through_the_project_index(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text("def fill(items, value):\n    items.append(value)\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "import os\nfrom helpers import fill\n\ndef run():\n    a = []\n    fill(a, input())\n    os.system(a[0])\n",
        encoding="utf-8",
    )

    findings = engine.analyze_project(tmp_path, [PLUGINS]).findings

    assert [(f.rule_id, f.span.start_line, f.metadata.get("through")) for f in findings] == [
        ("command-injection", 7, None)
    ]


# --------------------------------------------------------------------------- with the rest


def test_refutation_still_judges_container_borne_values() -> None:
    assert check_lines(
        "import os\n\ndef f():\n    a = []\n    a.append(input())\n    x = a[0]\n    if x.isdigit():\n        os.system(x)\n"
    ) == []
    assert check_lines("import os\n\ndef f():\n    a = []\n    a.append(input())\n    os.system(a[0])\n") == [
        ("command-injection", 6)
    ]
    assert check_lines("import os\n\ndef f():\n    a = []\n    a.append(input())\n    os.system(len(a))\n") == []
