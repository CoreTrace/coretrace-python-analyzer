"""Command-line entry points: the parameters of click and Typer commands are argv input."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import EntryPoint, Model, TaintKind

# A command-line tool is expected to open the paths it is given: argv input carries every
# kind but PATH.
ARGV_KINDS = TaintKind.ALL & ~TaintKind.PATH

_COMMANDS = (
    "click.command",
    "click.group",
    "click.command.command",
    "click.group.command",
    "click.group.group",
    "click.Group.command",
    "typer.Typer.command",
    "typer.Typer.callback",
)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class CliModels(ModelPlugin):
    name: ClassVar[str] = "cli-models"
    models: ClassVar[tuple[Model, ...]] = tuple(
        EntryPoint(_sym(command), "argv", ARGV_KINDS) for command in _COMMANDS
    )
