from __future__ import annotations

from coretrace_python.ir.model import (
    BinaryOp,
    Call,
    Compare,
    Constant,
    GetAttr,
    GetItem,
    Global,
    Instruction,
    LoadLocal,
    ModuleIR,
    Return,
    StoreLocal,
    UnaryOp,
    Value,
)


def _value(value: Value) -> str:
    return f"%{value.id}"


def _instruction(instruction: Instruction) -> str:
    if isinstance(instruction, Constant):
        return f"{_value(instruction.result)} = const {instruction.value!r}"
    if isinstance(instruction, Global):
        return f"{_value(instruction.result)} = global {instruction.name!r}"
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
    if isinstance(instruction, LoadLocal):
        return f'{_value(instruction.result)} = load_local "{instruction.name}"'
    if isinstance(instruction, StoreLocal):
        return f'store_local "{instruction.name}", {_value(instruction.value)}'
    if isinstance(instruction, Return):
        return "return" if instruction.value is None else f"return {_value(instruction.value)}"
    raise TypeError(f"unknown instruction: {instruction!r}")


def format_module(module: ModuleIR) -> str:
    functions: list[str] = []
    for function in module.functions:
        parameters = ", ".join(_value(parameter) for parameter in function.parameters)
        lines = [f"func @{function.name}({parameters}) {{"]
        for block in function.blocks:
            lines.append(f"{block.name}:")
            lines.extend(f"    {_instruction(instruction)}" for instruction in block.instructions)
        lines.append("}")
        functions.append("\n".join(lines))
    return "\n\n".join(functions)
