from __future__ import annotations

from coretrace_python.ir.model import (
    Assert,
    BinaryOp,
    BoolOp,
    Branch,
    BuildDict,
    BuildList,
    BuildTuple,
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
    SetAttr,
    SetItem,
    StoreLocal,
    Symbol,
    Terminator,
    UnaryOp,
    Undefined,
    Value,
    WithEnter,
    WithExit,
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
        parts = [_value(argument) for argument in instruction.arguments]
        for name, value in instruction.keywords:
            parts.append(f"{name}={_value(value)}" if name is not None else f"**{_value(value)}")
        return f"{_value(instruction.result)} = call {_value(instruction.callee)}({', '.join(parts)})"
    if isinstance(instruction, BoolOp):
        values = ", ".join(_value(v) for v in instruction.values)
        return f"{_value(instruction.result)} = bool_op.{instruction.operator} {values}"
    if isinstance(instruction, BuildList | BuildTuple):
        kind = "build_list" if isinstance(instruction, BuildList) else "build_tuple"
        elements = ", ".join(_value(v) for v in instruction.elements)
        return f"{_value(instruction.result)} = {kind} {elements}".rstrip()
    if isinstance(instruction, BuildDict):
        items = ", ".join(f"{_value(k)}: {_value(v)}" for k, v in instruction.items)
        return f"{_value(instruction.result)} = build_dict {items}".rstrip()
    if isinstance(instruction, WithEnter):
        return f"{_value(instruction.result)} = with_enter {_value(instruction.context)}"
    if isinstance(instruction, WithExit):
        return f"with_exit {_value(instruction.context)}"
    if isinstance(instruction, SetAttr):
        return f"set_attr {_value(instruction.object)}, {instruction.attribute!r}, {_value(instruction.value)}"
    if isinstance(instruction, SetItem):
        return (
            f"set_item {_value(instruction.object)}, {_value(instruction.key)}, "
            f"{_value(instruction.value)}"
        )
    if isinstance(instruction, Assert):
        message = "" if instruction.message is None else f", {_value(instruction.message)}"
        return f"assert {_value(instruction.test)}{message}"
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
