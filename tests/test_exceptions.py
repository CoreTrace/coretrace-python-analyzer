"""Acceptance tests for ``try`` with exception edges, and ``await`` / ``yield``.

``docs/architecture.md`` §3.2 PyHIR, §5 CFG (exception edges), §6 PyIR.

A ``try`` body is laid out like any block sequence; every block inside it carries
exception edges to the handler blocks, so a ``raise`` or a call in the body can reach a
handler. ``except E as name`` binds ``name`` to a ``catch`` value; the handlers, the
``else`` body and the ``finally`` body all join after the statement (``finally`` runs on
the normal path only, exceptional exits are approximated). Exception edges carry the
exit state of the raising block, so data produced in the body reaches handlers.

Expected to remain red until ``Try``, ``Await`` and ``Yield`` reach PyHIR, the CFG and PyIR.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cfg import CFG, BlockId, Jump, Raise, Return, build_cfg
from coretrace_python.cli import main
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.semantic.scopes import BindingKind, analyze_scopes
from coretrace_python.source import SourceManager

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


@pytest.fixture(autouse=True)
def require_try() -> None:
    if not hasattr(nodes, "Try") or not hasattr(nodes, "Await"):
        pytest.fail("Try, Await and Yield are not in PyHIR yet")


def build(source_text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("exc.py", source_text))


def function(source_text: str) -> nodes.Function:
    return next(s for s in build(source_text).body if isinstance(s, nodes.Function))


def cfg_for(source_text: str) -> CFG:
    return build_cfg(function(source_text))


def emit(source_text: str, tmp_path: Path, capsys, *flags: str) -> str:  # type: ignore[no-untyped-def]
    path = tmp_path / "exc.py"
    path.write_text(source_text, encoding="utf-8")
    assert main(["--emit-ir", *flags, str(path)]) == 0, capsys.readouterr().err
    return str(capsys.readouterr().out)


def b(name: str) -> BlockId:
    return BlockId(name)


# --------------------------------------------------------------------------- PyHIR


def test_try_node_shape() -> None:
    f = function(
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except ValueError as error:\n"
        "        handle(error)\n"
        "    except (TypeError, KeyError):\n"
        "        pass\n"
        "    except:\n"
        "        pass\n"
        "    else:\n"
        "        ok()\n"
        "    finally:\n"
        "        done()\n"
    )
    statement = f.body[0]
    assert isinstance(statement, nodes.Try)
    assert len(statement.body) == 1 and len(statement.orelse) == 1 and len(statement.finalbody) == 1
    first, second, bare = statement.handlers
    assert isinstance(first, nodes.ExceptHandler)
    assert isinstance(first.type, nodes.Name) and first.name == "error"
    assert isinstance(second.type, nodes.Tuple) and second.name is None
    assert bare.type is None and bare.name is None
    assert first.span.start_line == 4


def test_await_and_yield_nodes() -> None:
    f = function("async def f(x):\n    y = await x\n    yield y\n    yield\n")
    assign, first, second = f.body
    assert isinstance(assign, nodes.Assign) and isinstance(assign.value, nodes.Await)
    assert isinstance(first, nodes.ExpressionStatement) and isinstance(first.expression, nodes.Yield)
    assert isinstance(second, nodes.ExpressionStatement) and isinstance(second.expression, nodes.Yield)
    assert second.expression.value is None


def test_try_star_is_still_a_diagnostic() -> None:
    from coretrace_python.frontend import HIRBuildError

    with pytest.raises(HIRBuildError, match="except\\*"):
        build("def f():\n    try:\n        pass\n    except* ValueError:\n        pass\n")


# --------------------------------------------------------------------------- scopes


def test_handler_names_are_locals() -> None:
    module = build("def f():\n    try:\n        x = 1\n    except Exception as error:\n        y = error\n    finally:\n        z = 2\n")
    scopes = analyze_scopes(module)
    f = next(s for s in scopes.children(scopes.module_scope.id) if s.name == "f")

    assert f.bindings["error"].kind is BindingKind.LOCAL
    assert {"x", "y", "z"} <= set(f.bindings)


# --------------------------------------------------------------------------- CFG


def test_try_body_blocks_have_exception_edges_to_the_handlers() -> None:
    cfg = cfg_for(
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except ValueError:\n"
        "        recover()\n"
        "    except KeyError:\n"
        "        other()\n"
        "    after()\n"
    )
    entry = cfg.block(cfg.entry)

    assert isinstance(entry.terminator, Jump)
    body = cfg.block(entry.terminator.target)
    assert body.id == b("try_1")
    assert body.exception_targets == (b("handler_1"), b("handler_2"))
    assert cfg.successors(body.id) == (b("after_1"), b("handler_1"), b("handler_2"))
    for handler in ("handler_1", "handler_2"):
        assert cfg.predecessors(b(handler)) == (b("try_1"),)
        assert isinstance(cfg.block(b(handler)).terminator, Jump)
        assert cfg.block(b(handler)).terminator.target == b("after_1")  # type: ignore[union-attr]
    assert cfg.predecessors(b("after_1")) == (b("try_1"), b("handler_1"), b("handler_2"))
    assert isinstance(cfg.block(b("after_1")).terminator, Return)


def test_raise_inside_try_reaches_the_handler() -> None:
    cfg = cfg_for("def f():\n    try:\n        raise ValueError()\n    except ValueError:\n        return 1\n    return 0\n")
    body = cfg.block(b("try_1"))

    assert isinstance(body.terminator, Raise)
    assert cfg.successors(body.id) == (b("handler_1"),)
    assert b("handler_1") in cfg.reachable()
    # The body always raises and the handler returns: the code after is dead.
    assert b("after_1") not in cfg.reachable()
    assert isinstance(cfg.block(b("handler_1")).terminator, Return)


def test_else_and_finally_join_on_the_normal_path() -> None:
    cfg = cfg_for(
        "def f():\n"
        "    try:\n"
        "        x = 1\n"
        "    except Exception:\n"
        "        x = 2\n"
        "    else:\n"
        "        x = 3\n"
        "    finally:\n"
        "        x = 4\n"
        "    return x\n"
    )
    body = cfg.block(b("try_1"))
    assert isinstance(body.terminator, Jump)
    orelse = cfg.block(body.terminator.target)
    assert orelse.id == b("else_1")
    assert body.exception_targets == (b("handler_1"),)
    assert orelse.exception_targets == ()
    assert isinstance(orelse.terminator, Jump) and orelse.terminator.target == b("finally_1")
    handler = cfg.block(b("handler_1"))
    assert isinstance(handler.terminator, Jump) and handler.terminator.target == b("finally_1")
    final = cfg.block(b("finally_1"))
    assert [type(s).__name__ for s in final.statements] == ["Assign"]
    assert isinstance(final.terminator, Jump) and final.terminator.target == b("after_1")


def test_control_flow_inside_a_try_body_keeps_its_exception_edges() -> None:
    cfg = cfg_for(
        "def f(items):\n"
        "    try:\n"
        "        for item in items:\n"
        "            use(item)\n"
        "    except Exception:\n"
        "        pass\n"
        "    return 0\n"
    )
    inside = [block for block in cfg.blocks.values() if block.exception_targets]

    assert {block.id for block in inside} >= {b("try_1"), b("loop_1"), b("body_1")}
    assert all(block.exception_targets == (b("handler_1"),) for block in inside)
    assert cfg.block(b("handler_1")).exception_targets == ()
    assert cfg.block(b("after_1")).exception_targets == ()


def test_exception_targets_must_exist() -> None:
    from coretrace_python.cfg import BasicBlock, CFGError

    span = function("def f():\n    pass\n").span
    entry = b("entry")
    with pytest.raises(CFGError, match="missing"):
        CFG(entry, {entry: BasicBlock(entry, (), Return(None, span), (b("missing"),))})


def test_dominance_sees_exception_edges() -> None:
    from coretrace_python.cfg import dominator_tree

    cfg = cfg_for("def f():\n    try:\n        a()\n    except Exception:\n        b()\n    c()\n")
    tree = dominator_tree(cfg)

    assert tree.idom(b("handler_1")) == b("try_1")
    assert tree.idom(b("after_1")) == b("try_1")
    assert tree.frontier(b("handler_1")) == frozenset({b("after_1")})


# --------------------------------------------------------------------------- PyIR


def test_emit_ir_for_try_except(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit(
        "def f():\n"
        "    try:\n"
        "        x = risky()\n"
        "    except ValueError as error:\n"
        "        x = error\n"
        "    return x\n",
        tmp_path,
        capsys,
    )
    assert output == (
        "func @f() {\n"
        "entry:\n"
        "    jump try_1\n"
        "try_1 [except: handler_1]:\n"
        "    %0 = global 'risky'\n"
        "    %1 = call %0()\n"
        '    store_local "x", %1\n'
        "    jump after_1\n"
        "handler_1:\n"
        "    %2 = symbol @python.builtins.ValueError\n"
        "    %3 = catch %2\n"
        '    store_local "error", %3\n'
        '    %4 = load_local "error"\n'
        '    store_local "x", %4\n'
        "    jump after_1\n"
        "after_1:\n"
        '    %5 = load_local "x"\n'
        "    return %5\n"
        "}\n"
    )


def test_exception_edges_carry_the_exit_state_of_the_raising_block(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    # Approximation: a handler sees the values a body block had when control left it, so
    # data produced in the body (``cmd = input()``) is visible in the handler. The older
    # value of a name reassigned in the body is not modelled.
    output = emit(
        "def f(a):\n"
        "    x = a\n"
        "    try:\n"
        "        cmd = risky()\n"
        "        x = cmd\n"
        "    except Exception:\n"
        "        x = cmd\n"
        "    return x\n",
        tmp_path,
        capsys,
        "--ssa",
    )
    assert "phi" not in output.split("handler_1:")[1].split("after_1:")[0]
    assert 'after_1:\n    %5 = phi "x", [%2, try_1], [%2, handler_1]\n    return %5\n' in output


def test_emit_ir_for_await_and_yield(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("async def f(x):\n    y = await x\n    yield y\n    yield\n", tmp_path, capsys)
    assert "    %1 = await %0\n" in output
    assert '    %3 = yield %2\n' in output
    assert "    %4 = yield\n" in output


# --------------------------------------------------------------------------- taint


def test_taint_reaches_handlers_and_survives_finally() -> None:
    findings = engine.check(
        SourceManager().add_source(
            "exc.py",
            "import os\n\n"
            "def run():\n"
            "    cmd = input()\n"
            "    try:\n"
            "        risky()\n"
            "    except Exception:\n"
            "        os.system(cmd)\n"
            "    finally:\n"
            "        os.system(cmd)\n",
        ),
        [PLUGINS],
    )
    assert [(f.rule_id, f.span.start_line) for f in findings] == [
        ("command-injection", 8),
        ("command-injection", 10),
    ]


def test_await_propagates_taint() -> None:
    findings = engine.check(
        SourceManager().add_source(
            "aw.py", "import os\n\nasync def run(reader):\n    os.system(await reader.read(input()))\n"
        ),
        [PLUGINS],
    )
    assert [f.rule_id for f in findings] == ["command-injection"]


def test_check_no_longer_flags_try_as_unsupported() -> None:
    findings = engine.check(
        SourceManager().add_source("t.py", "def f():\n    try:\n        return 1\n    except Exception:\n        return 2\n"),
        [PLUGINS],
    )
    assert findings == ()
