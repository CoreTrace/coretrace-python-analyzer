"""Acceptance tests for the expression syntax found blocking real repositories
(``docs/architecture.md`` §3.2, §6; first post-roadmap syntax pass).

Seven repositories under ``tests-project/`` were mostly rejected by the frontend for a
handful of everyday constructs. This pass covers the ones that add no control flow:
f-strings, slices, dictionary unpacking, starred arguments and elements, ``raise ...
from`` and tuple loop targets. Each lowers to PyIR that the existing analyses consume
through their generic operand rules, so taint, dependence and refutation apply unchanged.

Expected to remain red until ``FormattedString``, ``Slice``, ``Starred``, ``Raise.cause``
and tuple loop targets exist in the HIR and lower to ``BuildString``, ``BuildSlice``,
``Call.starred``, ``BuildList.unpacked``, ``BuildDict.unpacked`` and ``Raise.cause``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.cli import main
from coretrace_python.findings.refutation import RefutationAnalysis, Status
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.model import (
    BuildDict,
    BuildList,
    Call,
    FunctionIR,
    GetItem,
    Instruction,
    Raise,
)
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
    from coretrace_python.hir.nodes import FormattedString, Slice, Starred
    from coretrace_python.ir.model import BuildSlice, BuildString
except ImportError as error:  # pragma: no cover - red until the syntax lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_syntax() -> None:
    if MISSING is not None:
        pytest.fail(f"expression syntax pass is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

MODELS = (
    Source(SymbolId("python.builtins.input"), "stdin"),
    Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
    Sink(SymbolId("python.subprocess.run"), TaintKind.COMMAND),
)


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("s.py", text))


def lower(text: str) -> FunctionIR:
    return lower_module(hir(text)).functions[0]


def instructions(function: FunctionIR, kind: type[Instruction]) -> list[Instruction]:
    return [i for block in function.blocks for i in block.instructions if isinstance(i, kind)]


def manager_for(text: str) -> AnalysisManager:
    manager = AnalysisManager(hir("import os\nimport subprocess\n\n" + text))
    manager.register(*engine.ALL_ANALYSES)
    registry = SecurityModelRegistry()
    registry.register(*MODELS)
    manager.provide(SecurityModelAnalysis, registry.freeze())
    return manager


def first_function(manager: AnalysisManager) -> nodes.Function:
    return next(s for s in manager.module.body if isinstance(s, nodes.Function))


def flow_lines(text: str) -> list[int]:
    manager = manager_for(text)
    return sorted(f.location.start_line for f in manager.get(TaintAnalysis, first_function(manager)).flows)


def verdicts(text: str) -> list[Status]:
    manager = manager_for(text)
    return [v.status for v in manager.get(RefutationAnalysis, first_function(manager)).all()]


def emit(text: str, tmp_path: Path, capsys) -> str:  # type: ignore[no-untyped-def]
    source = tmp_path / "e.py"
    source.write_text(text, encoding="utf-8")
    assert main(["--emit-ir", str(source)]) == 0
    return capsys.readouterr().out


# --------------------------------------------------------------------------- f-strings


def test_fstrings_become_formatted_strings_with_their_parts() -> None:
    module = hir("def f(host, n):\n    return f'ping {host} -c {n:>{n}} done'\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    returned = function.body[0]
    assert isinstance(returned, nodes.Return)
    text = returned.value

    assert isinstance(text, FormattedString)
    kinds = [type(part).__name__ for part in text.parts]
    assert kinds == ["Constant", "Name", "Constant", "Name", "Name", "Constant"]
    assert [p.value for p in text.parts if isinstance(p, nodes.Constant)] == ["ping ", " -c ", " done"]


def test_fstrings_lower_to_build_string(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    (built,) = instructions(lower("def f(host):\n    return f'ping {host}'\n"), BuildString)
    assert isinstance(built, BuildString) and len(built.parts) == 2
    output = emit("def f(host):\n    return f'ping {host}'\n", tmp_path, capsys)
    assert output == (
        "func @f(%0) {\n"
        "entry:\n"
        "    %1 = const 'ping '\n"
        "    %2 = build_string %1, %0\n"
        "    return %2\n"
        "}\n"
    )


def test_taint_and_refutation_flow_through_fstrings() -> None:
    assert flow_lines("def f():\n    host = input()\n    os.system(f'ping {host}')\n") == [6]
    assert verdicts("def f():\n    host = input()\n    if host.isdigit():\n        os.system(f'ping -c {host}')\n") == [
        Status.REFUTED
    ]
    assert flow_lines("def f():\n    n = 3\n    os.system(f'ping -c {n}')\n") == []


# --------------------------------------------------------------------------- slices


def test_slices_lower_to_build_slice_keys(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    module = hir("def f(x, a):\n    return x[1:3], x[::2], x[a:]\n")
    returned = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, nodes.Tuple)
    first, second, third = returned.value.elements
    assert all(isinstance(e, nodes.Subscript) and isinstance(e.key, Slice) for e in (first, second, third))
    assert isinstance(third.key, Slice) and third.key.upper is None and third.key.step is None  # type: ignore[union-attr]

    (built,) = instructions(lower("def f(x):\n    return x[1:]\n"), BuildSlice)
    assert isinstance(built, BuildSlice) and built.upper is None and built.step is None
    output = emit("def f(x):\n    return x[1:]\n", tmp_path, capsys)
    assert output == (
        "func @f(%0) {\n"
        "entry:\n"
        "    %1 = const 1\n"
        "    %2 = build_slice %1, none, none\n"
        "    %3 = get_item %0, %2\n"
        "    return %3\n"
        "}\n"
    )


def test_taint_flows_through_slices() -> None:
    assert flow_lines("def f():\n    cmd = input()\n    os.system(cmd[1:])\n") == [6]
    assert flow_lines("def f():\n    cmd = input()\n    os.system('ls'[0:2])\n") == []


# --------------------------------------------------------------------------- unpacking


def test_dict_unpacking_and_starred_elements_lower_with_unpacked_operands() -> None:
    function = lower("def f(base, extra, xs):\n    d = {**base, 'k': 1}\n    l = [*xs, 2]\n    t = (*xs,)\n    return d, l, t\n")

    (build_dict,) = instructions(function, BuildDict)
    (build_list,) = instructions(function, BuildList)
    assert isinstance(build_dict, BuildDict) and len(build_dict.unpacked) == 1 and len(build_dict.items) == 1
    assert isinstance(build_list, BuildList) and len(build_list.unpacked) == 1 and len(build_list.elements) == 1
    module = hir("def f(base):\n    return {**base}\n")
    returned = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, nodes.Dict)
    ((key, _),) = returned.value.items
    assert key is None


def test_taint_flows_through_unpacked_collections() -> None:
    assert flow_lines("def f():\n    base = {'cmd': input()}\n    d = {**base, 'x': 1}\n    os.system(d['cmd'])\n") == [7]
    assert flow_lines("def f():\n    xs = [input()]\n    l = [*xs, 'ls']\n    os.system(l[0])\n") == [7]
    assert flow_lines("def f():\n    base = {'cmd': 'ls'}\n    d = {**base}\n    os.system(d['cmd'])\n") == []


def test_starred_call_arguments_are_kept_apart_and_reach_sinks() -> None:
    function = lower("def f(args, kw):\n    return g(1, *args, key=2, **kw)\n")
    (call,) = instructions(function, Call)
    assert isinstance(call, Call)
    assert len(call.arguments) == 1 and len(call.starred) == 1 and len(call.keywords) == 2
    assert len(call.argument_values()) == 4

    module = hir("def f(args):\n    return g(*args)\n")
    returned = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, nodes.Call)
    assert isinstance(returned.value.arguments[0], Starred)


def test_taint_flows_through_starred_arguments_and_known_callees() -> None:
    assert flow_lines("def f():\n    parts = ['sh', '-c', input()]\n    subprocess.run(*parts)\n") == [6]
    assert flow_lines(
        "def run(cmd):\n    os.system(cmd)\n\ndef f():\n    args = [input()]\n    run(*args)\n"
    ) == []
    manager = manager_for("def run(cmd):\n    os.system(cmd)\n\ndef f():\n    args = [input()]\n    run(*args)\n")
    f = [s for s in manager.module.body if isinstance(s, nodes.Function)][1]
    assert [fl.location.start_line for fl in manager.get(TaintAnalysis, f).flows] == [9]


# --------------------------------------------------------------------------- raise from


def test_raise_from_keeps_its_cause(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    module = hir("def f(err):\n    raise ValueError('x') from err\n")
    raised = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(raised, nodes.Raise) and isinstance(raised.cause, nodes.Name)

    function = lower("def f(err):\n    raise ValueError('x') from err\n")
    terminator = function.blocks[0].terminator
    assert isinstance(terminator, Raise) and terminator.cause == function.parameters[0]

    output = emit("def f(err):\n    raise err from None\n", tmp_path, capsys)
    assert output.splitlines()[-2] == "    raise %0 from %1"


# --------------------------------------------------------------------------- tuple loop targets


def test_tuple_loop_targets_destructure_each_item() -> None:
    module = hir("def f(items):\n    for k, (v, w) in items:\n        print(k, v, w)\n")
    loop = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(loop, nodes.For)
    assert loop.target.identifier.isidentifier()
    first = loop.body[0]
    assert isinstance(first, nodes.Assign) and isinstance(first.target, nodes.Tuple)
    assert isinstance(first.value, nodes.Name) and first.value.identifier == loop.target.identifier

    function = lower("def f(items):\n    for k, v in items:\n        print(k, v)\n")
    assert len(instructions(function, GetItem)) == 2


def test_taint_flows_through_tuple_loop_targets() -> None:
    assert flow_lines("def f():\n    pairs = [('a', input())]\n    for name, cmd in pairs:\n        os.system(cmd)\n") == [7]


# --------------------------------------------------------------------------- end to end


def test_a_realistic_module_is_fully_analysed() -> None:
    findings = engine.check(
        SourceManager().add_source(
            "topology.py",
            "import os\nimport subprocess\n\n"
            "def probe(hosts, extra):\n"
            "    results = {}\n"
            "    for name, host in hosts.items():\n"
            "        try:\n"
            "            results[name] = subprocess.run(['ping', '-c', '1', host[:64]], *extra)\n"
            "        except OSError as err:\n"
            "            raise RuntimeError(f'cannot ping {host}') from err\n"
            "    return {**results, 'count': len(results)}\n",
        ),
        [PLUGINS],
    )
    assert [f.rule_id for f in findings if f.rule_id in ("syntax-error", "unsupported-syntax")] == []
