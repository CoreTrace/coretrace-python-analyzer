"""Security models and the global multi-kind taint engine (architecture §16, §17)."""

from coretrace_python.taint.engine import (
    Taint,
    TaintAnalysis,
    TaintFacts,
    TaintFlow,
    propagate_taint,
)
from coretrace_python.taint.models import (
    Model,
    ModelError,
    ModelTable,
    Sanitizer,
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintKind,
)

__all__ = [
    "Model",
    "ModelError",
    "ModelTable",
    "Sanitizer",
    "SecurityModelAnalysis",
    "SecurityModelRegistry",
    "Sink",
    "Source",
    "Taint",
    "TaintAnalysis",
    "TaintFacts",
    "TaintFlow",
    "TaintKind",
    "propagate_taint",
]
