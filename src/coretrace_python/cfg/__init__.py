"""Per-function control-flow graphs over PyHIR (architecture §5)."""

from coretrace_python.cfg.builder import CFGAnalysis, build_cfg
from coretrace_python.cfg.dominance import (
    EXIT,
    DominanceAnalysis,
    DominatorTree,
    PostDominanceAnalysis,
    dominator_tree,
    post_dominator_tree,
)
from coretrace_python.cfg.model import (
    CFG,
    BasicBlock,
    BlockId,
    Branch,
    CFGError,
    ForEach,
    Jump,
    Raise,
    Return,
    Terminator,
    targets,
)

__all__ = [
    "CFG",
    "EXIT",
    "BasicBlock",
    "BlockId",
    "Branch",
    "CFGAnalysis",
    "CFGError",
    "DominanceAnalysis",
    "DominatorTree",
    "ForEach",
    "Jump",
    "PostDominanceAnalysis",
    "Raise",
    "Return",
    "Terminator",
    "build_cfg",
    "dominator_tree",
    "post_dominator_tree",
    "targets",
]
