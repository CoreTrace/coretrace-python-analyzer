"""Acceptance tests for dominance (``docs/architecture.md`` §5).

``dominator_tree(cfg)`` computes immediate dominators and dominance frontiers over the
reachable blocks. ``post_dominator_tree(cfg)`` does the same on the reversed graph with a
virtual exit, which yields control dependence as the post-dominance frontier.

Expected to remain red until ``coretrace_python.cfg.dominance`` exists.
"""

from __future__ import annotations

import pytest

from coretrace_python.analysis import AnalysisManager
from coretrace_python.cfg import CFG, BlockId, Branch, CFGAnalysis, build_cfg
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.source import SourceManager

try:
    from coretrace_python.cfg.dominance import (
        EXIT,
        DominanceAnalysis,
        DominatorTree,
        PostDominanceAnalysis,
        dominator_tree,
        post_dominator_tree,
    )
except ImportError as error:  # pragma: no cover - red until dominance lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_dominance() -> None:
    if MISSING is not None:
        pytest.fail(f"dominance is not implemented yet: {MISSING}")


def function(source_text: str) -> nodes.Function:
    module = build_hir(SourceManager().add_source("dom.py", source_text))
    return next(s for s in module.body if isinstance(s, nodes.Function))


def cfg_for(source_text: str) -> CFG:
    return build_cfg(function(source_text))


def b(name: str) -> BlockId:
    return BlockId(name)


IF_ELSE = "def f(c, x):\n    if c:\n        x = 1\n    else:\n        x = 2\n    return x\n"
WHILE = "def f(n):\n    while n > 0:\n        n = n - 1\n    return n\n"
EARLY_RETURN = "def f(a):\n    if a:\n        return 1\n    return 0\n"


# --------------------------------------------------------------------------- dominators


def test_entry_has_no_dominator_and_dominates_everything() -> None:
    tree = dominator_tree(cfg_for(IF_ELSE))

    assert isinstance(tree, DominatorTree)
    assert tree.root == b("entry")
    assert tree.idom(b("entry")) is None
    for block in ("then_1", "else_1", "merge_1"):
        assert tree.dominates(b("entry"), b(block))
    assert tree.dominates(b("entry"), b("entry"))


def test_if_else_immediate_dominators_and_frontiers() -> None:
    tree = dominator_tree(cfg_for(IF_ELSE))

    assert tree.idom(b("then_1")) == b("entry")
    assert tree.idom(b("else_1")) == b("entry")
    assert tree.idom(b("merge_1")) == b("entry")
    assert tree.children(b("entry")) == (b("then_1"), b("else_1"), b("merge_1"))
    assert tree.frontier(b("then_1")) == frozenset({b("merge_1")})
    assert tree.frontier(b("else_1")) == frozenset({b("merge_1")})
    assert tree.frontier(b("merge_1")) == frozenset()
    assert not tree.dominates(b("then_1"), b("merge_1"))


def test_loop_header_dominates_its_body_and_exit() -> None:
    tree = dominator_tree(cfg_for(WHILE))

    assert tree.idom(b("loop_1")) == b("entry")
    assert tree.idom(b("body_1")) == b("loop_1")
    assert tree.idom(b("exit_1")) == b("loop_1")
    assert tree.frontier(b("body_1")) == frozenset({b("loop_1")})
    assert tree.frontier(b("loop_1")) == frozenset({b("loop_1")})
    assert tree.dominates(b("loop_1"), b("exit_1"))


def test_unreachable_blocks_are_outside_the_tree() -> None:
    tree = dominator_tree(cfg_for("def f():\n    return 1\n    x = 2\n"))

    assert tree.blocks == (b("entry"),)
    assert not tree.dominates(b("entry"), b("dead_1"))
    with pytest.raises(KeyError):
        tree.idom(b("dead_1"))


def test_blocks_are_listed_in_dominator_tree_preorder() -> None:
    tree = dominator_tree(cfg_for(WHILE))
    assert tree.blocks == (b("entry"), b("loop_1"), b("body_1"), b("exit_1"))


def test_iterated_frontier_is_the_phi_placement_set() -> None:
    tree = dominator_tree(cfg_for("def f(c, d):\n    if c:\n        x = 1\n    if d:\n        x = 2\n    return x\n"))

    assert tree.iterated_frontier(frozenset({b("then_1")})) == frozenset({b("merge_1")})
    assert tree.iterated_frontier(frozenset({b("then_1"), b("then_2")})) == frozenset(
        {b("merge_1"), b("merge_2")}
    )


# --------------------------------------------------------------------------- post-dominators


def test_post_dominators_join_at_the_merge() -> None:
    tree = post_dominator_tree(cfg_for(IF_ELSE))

    assert tree.root == EXIT
    assert tree.idom(b("merge_1")) == EXIT
    assert tree.idom(b("then_1")) == b("merge_1")
    assert tree.idom(b("else_1")) == b("merge_1")
    assert tree.idom(b("entry")) == b("merge_1")
    assert tree.dominates(b("merge_1"), b("entry"))


def test_early_returns_post_dominate_through_the_virtual_exit() -> None:
    tree = post_dominator_tree(cfg_for(EARLY_RETURN))

    assert tree.idom(b("then_1")) == EXIT
    assert tree.idom(b("merge_1")) == EXIT
    assert tree.idom(b("entry")) == EXIT
    assert not tree.dominates(b("merge_1"), b("entry"))


def test_control_dependence_is_the_post_dominance_frontier() -> None:
    tree = post_dominator_tree(cfg_for(EARLY_RETURN))

    assert tree.frontier(b("then_1")) == frozenset({b("entry")})
    assert tree.frontier(b("merge_1")) == frozenset({b("entry")})
    assert tree.frontier(b("entry")) == frozenset()


def test_guard_before_sink_is_detected_by_dominance() -> None:
    # The §24 refutation example: the sink only runs when the guard passed.
    cfg = cfg_for(
        "def f(value):\n"
        "    if not value.isdigit():\n"
        "        return None\n"
        "    sink(value)\n"
        "    return value\n"
    )
    entry = cfg.block(cfg.entry).terminator
    assert isinstance(entry, Branch)
    tree = dominator_tree(cfg)

    assert tree.idom(entry.else_block) == cfg.entry
    assert post_dominator_tree(cfg).frontier(entry.else_block) == frozenset({cfg.entry})


# --------------------------------------------------------------------------- analyses


def test_dominance_analyses_require_the_cfg() -> None:
    module = build_hir(SourceManager().add_source("dom.py", IF_ELSE))
    manager = AnalysisManager(module)
    manager.register(CFGAnalysis, DominanceAnalysis, PostDominanceAnalysis)
    target = next(s for s in module.body if isinstance(s, nodes.Function))

    assert CFGAnalysis in DominanceAnalysis.requires
    assert CFGAnalysis in PostDominanceAnalysis.requires
    assert DominanceAnalysis.name == "cfg.dominance"
    assert PostDominanceAnalysis.name == "cfg.post_dominance"
    assert manager.get(DominanceAnalysis, target).idom(b("merge_1")) == b("entry")
    assert manager.get(PostDominanceAnalysis, target).idom(b("entry")) == b("merge_1")
