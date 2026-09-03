"""Call graph and function summaries (architecture §19, §20)."""

from coretrace_python.interprocedural.callgraph import (
    CallGraph,
    CallGraphAnalysis,
    CallSite,
    ExternalSymbol,
    KnownFunction,
    Target,
    UnknownTarget,
)
from coretrace_python.interprocedural.summaries import (
    ExternalCall,
    FunctionSummary,
    SummaryAnalysis,
    SummaryTable,
)

__all__ = [
    "CallGraph",
    "CallGraphAnalysis",
    "CallSite",
    "ExternalCall",
    "ExternalSymbol",
    "FunctionSummary",
    "KnownFunction",
    "SummaryAnalysis",
    "SummaryTable",
    "Target",
    "UnknownTarget",
]
