from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

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
class Return:
    result: None
    location: SourceSpan
    value: Value | None


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
    | LoadLocal
)
EffectInstruction: TypeAlias = StoreLocal | Return
Instruction: TypeAlias = ValueInstruction | EffectInstruction


@dataclass(frozen=True)
class BasicBlock:
    name: str
    instructions: list[Instruction]

    def __init__(self, name: str, instructions: list[Instruction] | None = None) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "instructions", instructions or [])


@dataclass(frozen=True)
class FunctionIR:
    name: str
    parameters: tuple[Value, ...]
    blocks: tuple[BasicBlock, ...]
    location: SourceSpan


@dataclass(frozen=True)
class ModuleIR:
    functions: tuple[FunctionIR, ...]
