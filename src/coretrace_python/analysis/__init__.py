"""Analysis infrastructure: typed providers managed as a lazy, cached dependency DAG."""

from coretrace_python.analysis.manager import (
    AnalysisError,
    AnalysisManager,
    CyclicDependencyError,
    MissingInputError,
    UndeclaredDependencyError,
    UnregisteredAnalysisError,
)
from coretrace_python.analysis.provider import (
    Analysis,
    AnalysisContext,
    AnyAnalysis,
    FunctionAnalysis,
    TransformationPass,
)

__all__ = [
    "Analysis",
    "AnalysisContext",
    "AnalysisError",
    "AnalysisManager",
    "AnyAnalysis",
    "CyclicDependencyError",
    "FunctionAnalysis",
    "MissingInputError",
    "TransformationPass",
    "UndeclaredDependencyError",
    "UnregisteredAnalysisError",
]
