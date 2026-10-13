"""The constant text a string starts with (architecture §18): what ``+`` and f-strings
build from string literals and from module-level names bound once to one. Anything
else, a parameter, a call result, an import, ``%`` or ``format``, is text of unknown
value."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.abstract.module_constants import module_bindings
from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.ir.lowering import PyIRAnalysis
from coretrace_python.ir.model import (
    BinaryOp,
    BuildString,
    Constant,
    Global,
    Instruction,
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
    """The module-level names bound once and never rebound (``module_bindings``) to a
    string literal, with that literal."""

    name: ClassVar[str] = "abstract.module_strings"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({PyIRAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> Mapping[str, str]:
        bound, _ = module_bindings(ctx)
        return MappingProxyType(
            {
                name: made.value
                for name, made in bound.items()
                if isinstance(made, Constant) and isinstance(made.value, str)
            }
        )
