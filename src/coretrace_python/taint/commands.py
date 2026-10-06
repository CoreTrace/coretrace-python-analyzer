"""The command a process is started with, as a list or tuple display spells it: one
reading that the rules about processes share. Each element keeps its place, unpacked
literals included; an unpacked iterable of unknown contents stands for any number of
elements, perhaps none. A display that anything else may change before the call (any
other use of it) spells no command."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from coretrace_python.ir.defuse import DefUse
from coretrace_python.ir.model import BuildList, BuildTuple, Instruction, Value


@dataclass(frozen=True)
class CommandPart:
    """One element of a command, or, when ``known`` is false, an unpacked iterable of
    unknown contents standing for any number of elements."""

    value: Value
    known: bool = True


def command_parts(
    value: Value, defs: Mapping[Value, Instruction], uses: DefUse
) -> tuple[CommandPart, ...] | None:
    """The elements of the command ``value`` spells, in order, or None when it is not a
    list or tuple display used only there."""

    made = defs.get(value)
    if not isinstance(made, BuildList | BuildTuple) or len(uses.uses(value)) != 1:
        return None
    if len(made.unpacked_at) != len(made.unpacked):
        return None
    plain, unpacked = iter(made.elements), iter(made.unpacked)
    parts: list[CommandPart] = []
    for index in range(len(made.elements) + len(made.unpacked)):
        if index not in made.unpacked_at:
            parts.append(CommandPart(next(plain)))
            continue
        iterable = next(unpacked)
        nested = command_parts(iterable, defs, uses)
        parts.extend(nested if nested is not None else (CommandPart(iterable, known=False),))
    return tuple(parts)
