"""Python-aware intermediate representation."""

from coretrace_python.ir.model import PYIR_SCHEMA_VERSION, BasicBlock, FunctionIR, ModuleIR, Value

__all__ = ["PYIR_SCHEMA_VERSION", "BasicBlock", "FunctionIR", "ModuleIR", "Value"]
