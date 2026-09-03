"""Per-function control-flow graphs over PyHIR (architecture §5)."""

from coretrace_python.cfg.builder import CFGAnalysis, build_cfg
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
    "BasicBlock",
    "BlockId",
    "Branch",
    "CFGAnalysis",
    "CFGError",
    "ForEach",
    "Jump",
    "Raise",
    "Return",
    "Terminator",
    "build_cfg",
    "targets",
]
