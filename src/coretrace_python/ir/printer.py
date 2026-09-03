from __future__ import annotations

from coretrace_python.ir.model import (
    BinaryOp,
    Branch,
    Call,
    Compare,
    Constant,
    ForNext,
    GetAttr,
    GetItem,
    GetIter,
    Global,
    Instruction,
    Jump,
    LoadLocal,
    ModuleIR,
    Phi,
    Raise,
    Return,
    StoreLocal,
    Symbol,
    Terminator,
    UnaryOp,
    Undefined,
    Value,
)


def _value(value: Value) -> str:
    return f"%{value.id}"


def _instruction(instruction: Instruction) -> str:
    if isinstance(instruction, Constant):
        return f"{_value(instruction.result)} = const {instruction.value!r}"
    if isinstance(instruction, Global):
        return f"{_value(instruction.result)} = global {instruction.name!r}"
    if isinstance(instruction, Symbol):
        return f"{_value(instruction.result)} = symbol @{instruction.symbol_id}"
    if isinstance(instruction, BinaryOp):
        return (
            f"{_value(instruction.result)} = binary.{instruction.operator} "
            f"{_value(instruction.left)}, {_value(instruction.right)}"
        )
    if isinstance(instruction, UnaryOp):
        return (
            f"{_value(instruction.result)} = unary.{instruction.operator} "
            f"{_value(instruction.operand)}"
        )
    if isinstance(instruction, Compare):
        return (
            f"{_value(instruction.result)} = compare.{instruction.operator} "
            f"{_value(instruction.left)}, {_value(instruction.right)}"
        )
    if isinstance(instruction, Call):
        arguments = ", ".join(_value(argument) for argument in instruction.arguments)
        return f"{_value(instruction.result)} = call {_value(instruction.callee)}({arguments})"
    if isinstance(instruction, GetAttr):
        return (
            f"{_value(instruction.result)} = get_attr {_value(instruction.object)}, "
            f"{instruction.attribute!r}"
        )
    if isinstance(instruction, GetItem):
        return (
            f"{_value(instruction.result)} = get_item {_value(instruction.object)}, "
            f"{_value(instruction.key)}"
        )
    if isinstance(instruction, GetIter):
        return f"{_value(instruction.result)} = get_iter {_value(instruction.iterable)}"
    if isinstance(instruction, LoadLocal):
        return f'{_value(instruction.result)} = load_local "{instruction.name}"'
    if isinstance(instruction, StoreLocal):
        return f'store_local "{instruction.name}", {_value(instruction.value)}'
    if isinstance(instruction, Phi):
        incoming = ", ".join(f"[{_value(v)}, {b}]" for v, b in instruction.incoming)
        return f'{_value(instruction.result)} = phi "{instruction.name}", {incoming}'
    if isinstance(instruction, Undefined):
        return f'{_value(instruction.result)} = undefined "{instruction.name}"'
    raise TypeError(f"unknown instruction: {instruction!r}")


def _terminator(terminator: Terminator) -> str:
    if isinstance(terminator, Return):
        return "return" if terminator.value is None else f"return {_value(terminator.value)}"
    if isinstance(terminator, Branch):
        return (
            f"branch {_value(terminator.condition)}, "
            f"{terminator.then_block}, {terminator.else_block}"
        )
    if isinstance(terminator, Jump):
        return f"jump {terminator.target}"
    if isinstance(terminator, Raise):
        return "raise" if terminator.exception is None else f"raise {_value(terminator.exception)}"
    if isinstance(terminator, ForNext):
        prefix = "" if terminator.result is None else f"{_value(terminator.result)} = "
        return (
            f'{prefix}for_next {_value(terminator.iterator)} -> "{terminator.target}", '
            f"{terminator.body}, {terminator.exit}"
        )
    raise TypeError(f"unknown terminator: {terminator!r}")


def format_module(module: ModuleIR) -> str:
    functions: list[str] = []
    for function in module.functions:
        parameters = ", ".join(_value(parameter) for parameter in function.parameters)
        lines = [f"func @{function.name}({parameters}) {{"]
        for block in function.blocks:
            lines.append(f"{block.id}:")
            lines.extend(f"    {_instruction(instruction)}" for instruction in block.instructions)
            lines.append(f"    {_terminator(block.terminator)}")
        lines.append("}")
        functions.append("\n".join(lines))
    return "\n\n".join(functions)
