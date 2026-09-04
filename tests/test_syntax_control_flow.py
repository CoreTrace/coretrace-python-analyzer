"""Acceptance tests for the control-flow syntax found blocking real repositories
(``docs/architecture.md`` §3.2, §5, §6; second post-roadmap syntax pass).

Conditional expressions and comprehensions carry control flow inside an expression. The
HIR keeps them as they are, ``Conditional`` and ``Comprehension``, so scopes stay
faithful; the CFG builder lays them out as real blocks, a branch or a loop writing a
synthetic local that the expression then reads, so PyIR, SSA, taint and refutation see
ordinary control flow. Lambdas and nested function definitions become ``MakeFunction``
values whose bodies are not analysed yet; assignments to ``global`` names become
``SetGlobal``; set literals build ``BuildSet``; a chained assignment assigns each target
from one hidden local.

Expected to remain red until ``Conditional``, ``Lambda``, ``Set``, dictionary and tuple
target comprehensions, ``MakeFunction``, ``BuildSet`` and ``SetGlobal`` exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import analyzable_functions, lower_module
from coretrace_python.ir.model import Branch, ForNext, FunctionIR, Phi
from coretrace_python.ir.printer import format_module
from coretrace_python.semantic.scopes import BindingKind, ResolutionKind, ScopeKind, analyze_scopes
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
    from coretrace_python.hir.nodes import Conditional, Lambda, Set
    from coretrace_python.ir.model import BuildSet, MakeFunction, SetGlobal
except ImportError as error:  # pragma: no cover - red until the syntax lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_syntax() -> None:
    if MISSING is not None:
        pytest.fail(f"control-flow syntax pass is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

MODELS = (
    Source(SymbolId("python.builtins.input"), "stdin"),
    Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
)


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("s.py", text))


def lower(text: str, *, ssa: bool = False) -> FunctionIR:
    return lower_module(hir(text), ssa=ssa).functions[0]


def printed(text: str) -> str:
    return format_module(lower_module(hir(text)))


def manager_for(text: str) -> AnalysisManager:
    manager = AnalysisManager(hir("import os\n\n" + text))
    manager.register(*engine.ALL_ANALYSES)
    registry = SecurityModelRegistry()
    registry.register(*MODELS)
    manager.provide(SecurityModelAnalysis, registry.freeze())
    return manager


def flow_lines(text: str, name: str | None = None) -> list[int]:
    manager = manager_for(text)
    functions = [s for s in manager.module.body if isinstance(s, nodes.Function)]
    function = functions[0] if name is None else next(f for f in functions if f.name == name)
    return sorted(f.location.start_line for f in manager.get(TaintAnalysis, function).flows)


def notes(text: str) -> list[str]:
    findings = engine.check(SourceManager().add_source("m.py", text), [PLUGINS])
    return [f.message for f in findings if f.rule_id in ("syntax-error", "unsupported-syntax")]


def first_statement(text: str) -> nodes.Statement:
    function = hir(text).body[0]
    assert isinstance(function, nodes.Function)
    return function.body[0]


# --------------------------------------------------------------------------- conditional expressions


def test_conditional_expressions_are_kept_in_the_hir_and_branch_in_the_cfg() -> None:
    returned = first_statement("def f(a, b, c):\n    return a if c else b\n")
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, Conditional)
    assert isinstance(returned.value.test, nodes.Name) and returned.value.test.identifier == "c"

    function = lower("def f(a, b, c):\n    return a if c else b\n", ssa=True)

    assert any(isinstance(b.terminator, Branch) for b in function.blocks)
    assert any(isinstance(i, Phi) for b in function.blocks for i in b.instructions)


def test_taint_flows_through_either_branch_of_a_conditional() -> None:
    assert flow_lines("def f(flag):\n    cmd = 'ls' if flag else input()\n    os.system(cmd)\n") == [5]
    assert flow_lines("def f(flag):\n    cmd = 'ls' if flag else 'pwd'\n    os.system(cmd)\n") == []
    assert flow_lines("def f(flag):\n    os.system(input() if flag else 'ls')\n") == [4]


def test_conditionals_nest_inside_other_expressions() -> None:
    assert flow_lines("def f(a, b):\n    os.system('ping ' + (input() if a else ('x' if b else 'y')))\n") == [4]


def test_conditionals_in_loop_conditions_are_recomputed_each_iteration() -> None:
    assert notes("def f(x):\n    while (x if x else 1):\n        x = x - 1\n") == []


# --------------------------------------------------------------------------- lambdas and nested functions


def test_lambdas_have_their_own_scope_and_lower_to_function_values() -> None:
    module = hir("def f(items, k):\n    return sorted(items, key=lambda x: x + k)\n")
    scopes = analyze_scopes(module)
    f = next(s for s in scopes.children(scopes.module_scope.id) if s.name == "f")
    (lam,) = [s for s in scopes.children(f.id) if s.name == "<lambda>"]

    assert lam.kind is ScopeKind.FUNCTION
    assert lam.bindings["x"].kind is BindingKind.PARAMETER
    assert scopes.resolve(lam.id, "k").kind is ResolutionKind.FREE
    assert "x" not in f.bindings
    returned = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, nodes.Call)
    assert isinstance(returned.value.keywords[0].value, Lambda)

    text = printed("def f(items, k):\n    return sorted(items, key=lambda x: x + k)\n")
    assert 'make_function "lambda_2_30" [%1]' in text
    (made,) = [i for b in lower("def f():\n    return lambda: 1\n").blocks for i in b.instructions if isinstance(i, MakeFunction)]
    assert made.name == "lambda_2_12"


def test_calling_a_lambda_is_conservative() -> None:
    assert flow_lines("def f():\n    run = lambda c: c\n    os.system(run(input()))\n") == [5]


def test_nested_functions_become_values_and_the_outer_function_is_analysed() -> None:
    module = hir("def outer():\n    def inner(x):\n        return x\n    os.system(inner(input()))\n")
    assert [f.name for f in analyzable_functions(module)] == ["outer", "inner"]

    text = printed("def outer():\n    def inner(x):\n        return x\n    return inner\n")
    assert 'make_function "inner"' in text and 'store_local "inner"' in text
    assert flow_lines("def outer():\n    def inner(x):\n        return x\n    os.system(inner(input()))\n") == [6]
    assert notes("def outer():\n    def inner(x):\n        return x\n    return inner\n") == []


# --------------------------------------------------------------------------- comprehensions


def test_comprehensions_lower_to_loops_over_a_synthetic_result() -> None:
    function = lower("def f(items):\n    return [x.strip() for x in items if x]\n")
    text = printed("def f(items):\n    return [x.strip() for x in items if x]\n")

    assert any(isinstance(b.terminator, ForNext) for b in function.blocks)
    assert "append" in text and "build_list" in text


def test_dict_and_tuple_target_comprehensions_are_represented() -> None:
    returned = first_statement("def f(pairs):\n    return {k: v for k, v in pairs if k}\n")
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, nodes.Comprehension)
    comprehension = returned.value
    assert comprehension.kind == "dict"
    assert isinstance(comprehension.key, nodes.Name) and comprehension.key.identifier == "k"
    assert isinstance(comprehension.generators[0].target, nodes.Tuple)
    scopes = analyze_scopes(hir("def f(pairs):\n    return {k: v for k, v in pairs if k}\n"))
    f = next(s for s in scopes.children(scopes.module_scope.id) if s.name == "f")
    (inner,) = [s for s in scopes.children(f.id) if s.name == "<dictcomp>"]
    assert {"k", "v"} <= set(inner.bindings)


@pytest.mark.parametrize(
    "body",
    [
        "def f():\n    cmds = [c for c in input().split()]\n    os.system(cmds[0])\n",
        "def f():\n    cmds = {c for c in input().split()}\n    os.system(list(cmds)[0])\n",
        "def f():\n    pairs = [('a', input())]\n    d = {k: v for k, v in pairs}\n    os.system(d['a'])\n",
        "def f():\n    os.system(' '.join(c for c in input().split()))\n",
        "def f():\n    xs = [[input()]]\n    flat = [y for x in xs for y in x]\n    os.system(flat[0])\n",
        "def f():\n    cmds = [c.strip() for c in input().split() if c]\n    os.system(cmds[0])\n",
    ],
)
def test_taint_flows_through_comprehensions(body: str) -> None:
    found = flow_lines(body)
    assert len(found) == 1
    assert found[0] == body.count("\n") + 2


def test_comprehension_variables_do_not_leak_into_the_function() -> None:
    assert flow_lines("def f():\n    x = 'safe'\n    ys = [x for x in input().split()]\n    os.system(x)\n") == []
    assert flow_lines("def f():\n    x = 'safe'\n    ys = [x for x in input().split()]\n    os.system(ys[0])\n") == [6]


def test_clean_comprehensions_stay_clean() -> None:
    assert flow_lines("def f(items):\n    names = [i.name for i in items]\n    os.system(names[0])\n") == []


# --------------------------------------------------------------------------- globals, sets, chains


def test_assignments_to_global_names_lower_to_set_global() -> None:
    text = printed("counter = 0\n\ndef f():\n    global counter\n    counter = 1\n    counter += 1\n")
    assert text.count('set_global "counter"') == 2
    (store, _) = [i for b in lower("counter = 0\n\ndef f():\n    global counter\n    counter = 1\n    counter += 1\n").blocks for i in b.instructions if isinstance(i, SetGlobal)]
    assert store.name == "counter"
    assert notes("counter = 0\n\ndef f():\n    global counter\n    counter = input()\n") == []


def test_set_literals_build_sets_and_carry_taint() -> None:
    returned = first_statement("def f():\n    return {1, 2}\n")
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, Set)
    (built,) = [i for b in lower("def f():\n    return {1, 2}\n").blocks for i in b.instructions if isinstance(i, BuildSet)]
    assert len(built.elements) == 2
    assert "build_set" in printed("def f():\n    return {1, 2}\n")
    assert flow_lines("def f():\n    s = {input()}\n    os.system(list(s)[0])\n") == [5]


def test_chained_assignments_assign_every_target() -> None:
    function = hir("def f():\n    a = b = input()\n    return a, b\n").body[0]
    assert isinstance(function, nodes.Function)
    assigns = [s for s in function.body if isinstance(s, nodes.Assign)]
    assert len(assigns) == 3
    assert flow_lines("def f():\n    a = b = input()\n    os.system(a)\n    os.system(b)\n") == [5, 6]


# --------------------------------------------------------------------------- end to end


def test_a_realistic_module_is_fully_analysed() -> None:
    assert (
        notes(
            "import os\nimport json\n\n"
            "state = {}\n\n"
            "def configure(settings):\n"
            "    global state\n"
            "    state = {k: v for k, v in settings.items() if not k.startswith('_')}\n"
            "    ordered = sorted(state, key=lambda k: k.lower())\n"
            "    label = ordered[0] if ordered else 'none'\n"
            "    tags = {t.strip() for t in label.split(',')}\n"
            "    first = last = label\n"
            "    def render(item):\n"
            "        return json.dumps(item)\n"
            "    return render(tags), first, last\n"
        )
        == []
    )
