"""Python-aware intermediate representation."""

from coretrace_python.ir.model import BasicBlock, FunctionIR, ModuleIR, Value
from coretrace_python.source import SourceSpan

__all__ = ["BasicBlock", "FunctionIR", "ModuleIR", "SourceSpan", "Value"]
