"""Module-level names whose value is known (architecture §18): the names bound once and
never rebound, and among them the ones bound to an immutable collection of constants,
which an allowlist reads."""

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
    BuildDict,
    BuildList,
    BuildSet,
    BuildTuple,
    Call,
    Constant,
    ForNext,
    Instruction,
    SetGlobal,
    StoreLocal,
    Symbol,
    Value,
)
from coretrace_python.semantic.symbols import SymbolId

FROZENSET = SymbolId("python.builtins.frozenset")


def module_bindings(ctx: AnalysisContext) -> tuple[Mapping[str, Instruction], Mapping[Value, Instruction]]:
    """The module-level names bound once and never rebound, by no other statement of the
    module body, no function assigning them as ``global``, no definition of that name,
    each with the instruction that makes its value; and the definitions of the module
    body's values. A module that does not lower entirely has none."""

    try:
        functions = [ctx.get(PyIRAnalysis, function) for function in analyzable_functions(ctx.module)]
    except (LoweringError, CFGError):
        return MappingProxyType({}), MappingProxyType({})
    body = next((function for function in functions if function.name == MODULE_BODY), None)
    if body is None:
        return MappingProxyType({}), MappingProxyType({})
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
    bound: dict[str, Instruction] = {}
    for name, values in stored.items():
        value = values[0] if len(values) == 1 and name not in rebound else None
        made = defs.get(value) if value is not None else None
        if made is not None:
            bound[name] = made
    return MappingProxyType(bound), MappingProxyType(defs)


def constant_members(display: Instruction | None, defs: Mapping[Value, Instruction]) -> bool:
    """Whether ``display`` is a tuple, list or set display whose items are all constants,
    or a dict display whose keys are, with nothing unpacked into it: the members a
    membership test reads."""

    if isinstance(display, BuildList | BuildTuple | BuildSet):
        return not display.unpacked and all(isinstance(defs.get(e), Constant) for e in display.elements)
    if isinstance(display, BuildDict):
        return not display.unpacked and all(isinstance(defs.get(key), Constant) for key, _ in display.items)
    return False


def converts(call: Call, defs: Mapping[Value, Instruction], symbols: frozenset[SymbolId]) -> Value | None:
    """The one positional argument of ``call`` when it calls one of ``symbols`` with
    nothing else (``frozenset(x)``), otherwise ``None``."""

    callee = defs.get(call.callee)
    if not isinstance(callee, Symbol) or callee.symbol_id not in symbols:
        return None
    if len(call.arguments) != 1 or call.keywords or call.starred:
        return None
    return call.arguments[0]


class ModuleCollectionsAnalysis(Analysis[frozenset[str]]):
    """The module-level names bound once and never rebound (``module_bindings``) to an
    immutable collection of constants: a tuple display, or ``frozenset`` of a display
    whose members are constants (``constant_members``). A list, a set or a dict can still
    change after it is bound, so it is not one."""

    name: ClassVar[str] = "abstract.module_collections"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({PyIRAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> frozenset[str]:
        bound, defs = module_bindings(ctx)
        found: set[str] = set()
        for name, made in bound.items():
            collection: Instruction | None = made
            if isinstance(made, Call):
                argument = converts(made, defs, frozenset({FROZENSET}))
                collection = defs.get(argument) if argument is not None else None
            elif not isinstance(made, BuildTuple):
                continue
            if constant_members(collection, defs):
                found.add(name)
        return frozenset(found)
