"""The constant text a string starts with (architecture §18): what ``+`` and f-strings
build from string literals and from module-level names bound once to one. Anything
else, a parameter, a call result, an import, ``%`` or ``format``, is text of unknown
value."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.cfg import CFGError
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import (
    MODULE_BODY,
    LoweringError,
    PyIRAnalysis,
    analyzable_functions,
)
from coretrace_python.ir.model import (
    BinaryOp,
    BuildString,
    Constant,
    ForNext,
    Global,
    Instruction,
    SetGlobal,
    StoreLocal,
    Value,
)


def leading_text(value: Value, defs: Mapping[Value, Instruction], strings: Mapping[str, str]) -> tuple[str, bool]:
    """The constant text ``value`` starts with, and whether that text is all of it, given
    the definitions of the function's values and the module's ``strings``."""

    made = defs.get(value)
    if isinstance(made, Constant):
        return (made.value, True) if isinstance(made.value, str) else ("", False)
    if isinstance(made, Global):
        known = strings.get(made.name)
        return ("", False) if known is None else (known, True)
    if isinstance(made, BinaryOp) and made.operator == "add":
        left, whole = leading_text(made.left, defs, strings)
        if not whole:
            return left, False
        right, whole = leading_text(made.right, defs, strings)
        return left + right, whole
    if isinstance(made, BuildString):
        text = ""
        for part in made.parts:
            piece, whole = leading_text(part, defs, strings)
            text += piece
            if not whole:
                return text, False
        return text, True
    return "", False


class ModuleStringsAnalysis(Analysis[Mapping[str, str]]):
    """The module-level names bound once, to a string literal, and never rebound: by no
    other statement of the module body, no function assigning them as ``global``, no
    definition of that name. A module that does not lower entirely has none."""

    name: ClassVar[str] = "abstract.module_strings"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({PyIRAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> Mapping[str, str]:
        try:
            functions = [ctx.get(PyIRAnalysis, function) for function in analyzable_functions(ctx.module)]
        except (LoweringError, CFGError):
            return MappingProxyType({})
        body = next((function for function in functions if function.name == MODULE_BODY), None)
        if body is None:
            return MappingProxyType({})
        defs = {i.result: i for block in body.blocks for i in block.instructions if i.result is not None}
        stored: dict[str, list[Value | None]] = {}
        for block in body.blocks:
            for instruction in block.instructions:
                if isinstance(instruction, StoreLocal):
                    stored.setdefault(instruction.name, []).append(instruction.value)
            if isinstance(block.terminator, ForNext):
                # A ``for`` binds its target to each item.
                stored.setdefault(block.terminator.target, []).append(None)
        rebound = {
            i.name for function in functions for block in function.blocks for i in block.instructions
            if isinstance(i, SetGlobal)
        }
        rebound |= {s.name for s in ctx.module.body if isinstance(s, nodes.Function | nodes.Class)}
        found: dict[str, str] = {}
        for name, values in stored.items():
            value = values[0] if len(values) == 1 and name not in rebound else None
            made = defs.get(value) if value is not None else None
            if isinstance(made, Constant) and isinstance(made.value, str):
                found[name] = made.value
        return MappingProxyType(found)
