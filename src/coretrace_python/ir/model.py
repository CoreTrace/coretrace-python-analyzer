from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from coretrace_python.cfg import BlockId
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceSpan


@dataclass(frozen=True)
class Value:
    id: int


@dataclass(frozen=True)
class Constant:
    result: Value
    location: SourceSpan
    value: object


@dataclass(frozen=True)
class Global:
    result: Value
    location: SourceSpan
    name: str


@dataclass(frozen=True)
class Symbol:
    result: Value
    location: SourceSpan
    symbol_id: SymbolId


@dataclass(frozen=True)
class BinaryOp:
    result: Value
    location: SourceSpan
    operator: str
    left: Value
    right: Value


@dataclass(frozen=True)
class UnaryOp:
    result: Value
    location: SourceSpan
    operator: str
    operand: Value


@dataclass(frozen=True)
class Compare:
    result: Value
    location: SourceSpan
    operator: str
    left: Value
    right: Value


@dataclass(frozen=True)
class Call:
    result: Value
    location: SourceSpan
    callee: Value
    arguments: tuple[Value, ...]


@dataclass(frozen=True)
class GetAttr:
    result: Value
    location: SourceSpan
    object: Value
    attribute: str


@dataclass(frozen=True)
class GetItem:
    result: Value
    location: SourceSpan
    object: Value
    key: Value


@dataclass(frozen=True)
class GetIter:
    result: Value
    location: SourceSpan
    iterable: Value


@dataclass(frozen=True)
class LoadLocal:
    result: Value
    location: SourceSpan
    name: str


@dataclass(frozen=True)
class StoreLocal:
    result: None
    location: SourceSpan
    name: str
    value: Value


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
)
EffectInstruction: TypeAlias = StoreLocal
Instruction: TypeAlias = ValueInstruction | EffectInstruction


# --------------------------------------------------------------------------- terminators


@dataclass(frozen=True)
class Return:
    location: SourceSpan
    value: Value | None


@dataclass(frozen=True)
class Branch:
    location: SourceSpan
    condition: Value
    then_block: BlockId
    else_block: BlockId


@dataclass(frozen=True)
class Jump:
    location: SourceSpan
    target: BlockId


@dataclass(frozen=True)
class Raise:
    location: SourceSpan
    exception: Value | None


@dataclass(frozen=True)
class ForNext:
    """Store the next item of ``iterator`` into local ``target`` and enter ``body``, or ``exit``."""

    location: SourceSpan
    iterator: Value
    target: str
    body: BlockId
    exit: BlockId


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
