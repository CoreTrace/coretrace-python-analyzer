from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from typing import Any, TypeAlias, TypeVar

from coretrace_python.cfg import BlockId
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceSpan

# Bumped whenever the instruction set or its meaning changes; part of the cache key.
PYIR_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Value:
    id: int


class Operands:
    """Generic operand access for instructions and terminators."""

    def operands(self) -> tuple[Value, ...]:
        found: list[Value] = []
        for field_info in fields(self):  # type: ignore[arg-type]
            if field_info.name != "result":
                found.extend(_values_in(getattr(self, field_info.name)))
        return tuple(found)


def _values_in(value: object) -> list[Value]:
    if isinstance(value, Value):
        return [value]
    if isinstance(value, tuple):
        return [v for item in value for v in _values_in(item)]
    return []


def _map_values(value: Any, mapping: Callable[[Value], Value]) -> Any:
    if isinstance(value, Value):
        return mapping(value)
    if isinstance(value, tuple):
        return tuple(_map_values(item, mapping) for item in value)
    return value


N = TypeVar("N", bound=Operands)


def substitute(node: N, mapping: Callable[[Value], Value], *, include_result: bool = False) -> N:
    """Copy ``node`` with every operand (and optionally its result) passed through ``mapping``."""

    changes: dict[str, Any] = {}
    for field_info in fields(node):  # type: ignore[arg-type]
        value = getattr(node, field_info.name)
        if field_info.name == "result":
            if include_result and isinstance(value, Value):
                changes["result"] = mapping(value)
        else:
            changes[field_info.name] = _map_values(value, mapping)
    return replace(node, **changes)  # type: ignore[type-var]


@dataclass(frozen=True)
class Constant(Operands):
    result: Value
    location: SourceSpan
    value: object


@dataclass(frozen=True)
class Global(Operands):
    result: Value
    location: SourceSpan
    name: str


@dataclass(frozen=True)
class Symbol(Operands):
    result: Value
    location: SourceSpan
    symbol_id: SymbolId


@dataclass(frozen=True)
class BinaryOp(Operands):
    result: Value
    location: SourceSpan
    operator: str
    left: Value
    right: Value


@dataclass(frozen=True)
class UnaryOp(Operands):
    result: Value
    location: SourceSpan
    operator: str
    operand: Value


@dataclass(frozen=True)
class Compare(Operands):
    result: Value
    location: SourceSpan
    operator: str
    left: Value
    right: Value


@dataclass(frozen=True)
class Call(Operands):
    """``starred`` are ``*iterable`` arguments whose positions are unknown; keywords
    with a ``None`` name are ``**mapping`` arguments."""

    result: Value
    location: SourceSpan
    callee: Value
    arguments: tuple[Value, ...]
    keywords: tuple[tuple[str | None, Value], ...] = ()
    starred: tuple[Value, ...] = ()

    def argument_values(self) -> tuple[Value, ...]:
        return (*self.arguments, *self.starred, *(value for _, value in self.keywords))


@dataclass(frozen=True)
class BoolOp(Operands):
    result: Value
    location: SourceSpan
    operator: str
    values: tuple[Value, ...]


@dataclass(frozen=True)
class BuildList(Operands):
    result: Value
    location: SourceSpan
    elements: tuple[Value, ...]
    unpacked: tuple[Value, ...] = ()


@dataclass(frozen=True)
class BuildTuple(Operands):
    result: Value
    location: SourceSpan
    elements: tuple[Value, ...]
    unpacked: tuple[Value, ...] = ()


@dataclass(frozen=True)
class BuildDict(Operands):
    result: Value
    location: SourceSpan
    items: tuple[tuple[Value, Value], ...]
    unpacked: tuple[Value, ...] = ()


@dataclass(frozen=True)
class BuildSet(Operands):
    result: Value
    location: SourceSpan
    elements: tuple[Value, ...]
    unpacked: tuple[Value, ...] = ()


@dataclass(frozen=True)
class MakeFunction(Operands):
    """A function value: a lambda or a nested definition. ``captured`` are the values of
    the variables the body captures, at the definition point, in the order the nested
    function takes them as implicit parameters after its explicit ones."""

    result: Value
    location: SourceSpan
    name: str
    captured: tuple[Value, ...] = ()


@dataclass(frozen=True)
class BuildString(Operands):
    """An f-string: its constant and formatted parts, in order."""

    result: Value
    location: SourceSpan
    parts: tuple[Value, ...]


@dataclass(frozen=True)
class BuildSlice(Operands):
    result: Value
    location: SourceSpan
    lower: Value | None
    upper: Value | None
    step: Value | None


@dataclass(frozen=True)
class WithEnter(Operands):
    result: Value
    location: SourceSpan
    context: Value


@dataclass(frozen=True)
class Catch(Operands):
    """The exception bound by ``except type as name`` at the start of a handler."""

    result: Value
    location: SourceSpan
    type: Value | None


@dataclass(frozen=True)
class Await(Operands):
    result: Value
    location: SourceSpan
    value: Value


@dataclass(frozen=True)
class Yield(Operands):
    result: Value
    location: SourceSpan
    value: Value | None


@dataclass(frozen=True)
class GetAttr(Operands):
    result: Value
    location: SourceSpan
    object: Value
    attribute: str


@dataclass(frozen=True)
class GetItem(Operands):
    result: Value
    location: SourceSpan
    object: Value
    key: Value


@dataclass(frozen=True)
class GetIter(Operands):
    result: Value
    location: SourceSpan
    iterable: Value


@dataclass(frozen=True)
class LoadLocal(Operands):
    result: Value
    location: SourceSpan
    name: str


@dataclass(frozen=True)
class Phi(Operands):
    """Merge of the values of local ``name`` arriving from each predecessor (SSA only)."""

    result: Value
    location: SourceSpan
    name: str
    incoming: tuple[tuple[Value, BlockId], ...]


@dataclass(frozen=True)
class Undefined(Operands):
    """The value of local ``name`` on a path where it was never assigned (SSA only)."""

    result: Value
    location: SourceSpan
    name: str


@dataclass(frozen=True)
class StoreLocal(Operands):
    result: None
    location: SourceSpan
    name: str
    value: Value


@dataclass(frozen=True)
class SetAttr(Operands):
    result: None
    location: SourceSpan
    object: Value
    attribute: str
    value: Value


@dataclass(frozen=True)
class SetItem(Operands):
    result: None
    location: SourceSpan
    object: Value
    key: Value
    value: Value


@dataclass(frozen=True)
class WithExit(Operands):
    result: None
    location: SourceSpan
    context: Value


@dataclass(frozen=True)
class Assert(Operands):
    result: None
    location: SourceSpan
    test: Value
    message: Value | None


@dataclass(frozen=True)
class DelItem(Operands):
    result: None
    location: SourceSpan
    object: Value
    key: Value


@dataclass(frozen=True)
class DelAttr(Operands):
    result: None
    location: SourceSpan
    object: Value
    attribute: str


@dataclass(frozen=True)
class SetGlobal(Operands):
    """Assignment to a name declared ``global``."""

    result: None
    location: SourceSpan
    name: str
    value: Value


@dataclass(frozen=True)
class Import(Operands):
    """An import executed where it stands: ``module`` as written (relative dots
    included), the canonical ``symbol_id`` bound and the local ``name`` it binds."""

    result: None
    location: SourceSpan
    module: str
    symbol_id: SymbolId
    name: str


ValueInstruction: TypeAlias = (
    Constant
    | Global
    | Symbol
    | BinaryOp
    | UnaryOp
    | Compare
    | Call
    | GetAttr
    | GetItem
    | GetIter
    | LoadLocal
    | Phi
    | Undefined
    | BoolOp
    | BuildList
    | BuildTuple
    | BuildDict
    | BuildSet
    | BuildString
    | BuildSlice
    | MakeFunction
    | WithEnter
    | Catch
    | Await
    | Yield
)
EffectInstruction: TypeAlias = (
    StoreLocal | SetAttr | SetItem | WithExit | Assert | Import | SetGlobal | DelItem | DelAttr
)
Instruction: TypeAlias = ValueInstruction | EffectInstruction


# --------------------------------------------------------------------------- terminators


@dataclass(frozen=True)
class Return(Operands):
    location: SourceSpan
    value: Value | None


@dataclass(frozen=True)
class Branch(Operands):
    location: SourceSpan
    condition: Value
    then_block: BlockId
    else_block: BlockId


@dataclass(frozen=True)
class Jump(Operands):
    location: SourceSpan
    target: BlockId


@dataclass(frozen=True)
class Raise(Operands):
    location: SourceSpan
    exception: Value | None
    cause: Value | None = None


@dataclass(frozen=True)
class ForNext(Operands):
    """Store the next item of ``iterator`` into local ``target`` and enter ``body``, or ``exit``."""

    location: SourceSpan
    iterator: Value
    target: str
    body: BlockId
    exit: BlockId
    result: Value | None = None


Terminator: TypeAlias = Return | Branch | Jump | Raise | ForNext


@dataclass(frozen=True)
class BasicBlock:
    id: BlockId
    instructions: tuple[Instruction, ...]
    terminator: Terminator
    exception_targets: tuple[BlockId, ...] = ()


def successors(block: BasicBlock) -> tuple[BlockId, ...]:
    """Terminator targets followed by the exception edges of ``block``."""

    found = list(_terminator_targets(block.terminator))
    found.extend(t for t in block.exception_targets if t not in found)
    return tuple(found)


def _terminator_targets(terminator: Terminator) -> tuple[BlockId, ...]:
    if isinstance(terminator, Branch):
        return (terminator.then_block, terminator.else_block)
    if isinstance(terminator, Jump):
        return (terminator.target,)
    if isinstance(terminator, ForNext):
        return (terminator.body, terminator.exit)
    return ()


@dataclass(frozen=True)
class FunctionIR:
    name: str
    parameters: tuple[Value, ...]
    entry: BlockId
    blocks: tuple[BasicBlock, ...]
    location: SourceSpan


@dataclass(frozen=True)
class ModuleIR:
    functions: tuple[FunctionIR, ...]
