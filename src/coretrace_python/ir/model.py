from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from typing import Any, TypeAlias, TypeVar

from coretrace_python.cfg import BlockId
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceSpan


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
    result: Value
    location: SourceSpan
    callee: Value
    arguments: tuple[Value, ...]
    keywords: tuple[tuple[str | None, Value], ...] = ()

    def argument_values(self) -> tuple[Value, ...]:
        return (*self.arguments, *(value for _, value in self.keywords))


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


@dataclass(frozen=True)
class BuildTuple(Operands):
    result: Value
    location: SourceSpan
    elements: tuple[Value, ...]


@dataclass(frozen=True)
class BuildDict(Operands):
    result: Value
    location: SourceSpan
    items: tuple[tuple[Value, Value], ...]


@dataclass(frozen=True)
class WithEnter(Operands):
    result: Value
    location: SourceSpan
    context: Value


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
    | WithEnter
)
EffectInstruction: TypeAlias = StoreLocal | SetAttr | SetItem | WithExit | Assert
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
