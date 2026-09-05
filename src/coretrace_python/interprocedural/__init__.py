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
from coretrace_python.interprocedural.modulegraph import (
    ModuleGraph,
    build_module_graph,
    discover_files,
    discover_sources,
    project_symbol,
)
from coretrace_python.interprocedural.summaries import (
    ExternalCall,
    FunctionSummary,
    Mutation,
    NonlocalWrite,
    ProjectSummaries,
    SummaryAnalysis,
    SummaryIndex,
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
    "ModuleGraph",
    "Mutation",
    "NonlocalWrite",
    "ProjectSummaries",
    "SummaryAnalysis",
    "SummaryIndex",
    "SummaryTable",
    "Target",
    "UnknownTarget",
    "build_module_graph",
    "discover_files",
    "discover_sources",
    "project_symbol",
]
