"""Command injection: attacker-controlled input reaching a COMMAND sink.

What decides the result is what the attacker still controls in the command a process is
started with (issue #208). A string that a shell interprets, a string naming the program,
the program itself, or an operand the program runs as a command (after the host for
``ssh``, the program of a wrapper such as ``sudo``, any argument of a batch file) is a
command injection, ``high``. An element of an argument list run without a shell
otherwise injects at most an option: ``medium``, or ``high`` when ``OPTIONS`` establishes
that the program runs a command chosen through an option that fits there.

A value an option takes is judged by what ``OPTIONS`` establishes the option does with
it, whatever its prefix: run it (``sh -c``, ``cmd /c``, ``python -c``: ``high``), keep it
as data (``git commit -m``: refuted), or something not established (``medium``). After an
option ``OPTIONS`` does not describe, the finding is kept for review at the severity of a
free element; after options established to take no value (``rm -rf``, grouped short
options read as getopt reads them), the element stands alone. An element standing alone
is judged by its constant prefix: ``f"v{x}"`` is no option, the value of ``f"--output={x}"``
belongs to a fixed option, ``f"--{x}"`` leaves the option open. A ``hotspot`` verdict
lowers the confidence, never the severity, which each case sets.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar

from coretrace_python.abstract.strings import ModuleStringsAnalysis, leading_text
from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.findings.refutation import Status, Verdict
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import Arguments
from coretrace_python.ir.defuse import DefUseAnalysis
from coretrace_python.ir.model import Instruction, Symbol, Value
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import Assessment, PluginContext, TaintDetector
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TaintAnalysis, TaintFlow, TaintKind
from coretrace_python.taint.commands import CommandPart, command_parts


@dataclass(frozen=True)
class CommandOption:
    """An option of ``program``, after one of ``subcommands`` when any are given. An
    option that ``takes_value`` reads it from the next element, or after ``=`` or the
    short option in the same element, and ``single`` says one element can carry the option
    and its value; with ``rest``, every element after it is its value. What the program
    does with the value decides: with ``runs``, it runs a command the value chooses;
    with ``inert``, it only keeps it as data (a commit message); with neither, the effect
    is not established. An option that takes no value leaves the next element free."""

    program: str
    option: str
    runs: str | None = None
    subcommands: tuple[str, ...] = ()
    single: bool = True
    takes_value: bool = True
    inert: str | None = None
    rest: bool = False


def _flags(program: str, *options: str) -> tuple[CommandOption, ...]:
    return tuple(CommandOption(program, option, takes_value=False) for option in options)


_SHELLS = ("sh", "bash", "dash", "zsh", "ksh")

# Documented behaviours only: an option missing here is neither established to be
# dangerous, nor inert, nor to take no value.
OPTIONS: tuple[CommandOption, ...] = (
    CommandOption(
        "git", "-c", "sets any configuration variable, core.sshCommand included", single=False
    ),
    *(
        CommandOption("git", option, "runs the program it names", subcommands)
        for option, subcommands in (
            ("--upload-pack", ("clone", "fetch", "pull", "ls-remote")),
            ("--receive-pack", ("push",)),
            ("--exec", ("push",)),
        )
    ),
    *(
        CommandOption(
            "git", option, subcommands=(subcommand,), inert=f"is the {subcommand} message"
        )
        for subcommand in ("commit", "tag")
        for option in ("-m", "--message")
    ),
    *(
        CommandOption("gh", option, subcommands=(subcommand,), inert=inert)
        for subcommand, options, inert in (
            ("release", ("--title", "-t", "--notes", "-n"), "is text of the release"),
            ("workflow", ("--ref", "-r"), "names the branch or tag of the workflow"),
        )
        for option in options
    ),
    CommandOption("ssh", "-o", "sets options such as ProxyCommand, which runs a command"),
    *_flags("ssh", *(f"-{letter}" for letter in "46AaCfGgKkMNnqsTtVvXxYy")),
    CommandOption(
        "tar", "--to-command", "pipes each extracted file to the command it names (GNU tar)"
    ),
    CommandOption("tar", "--checkpoint-action", "runs the command of an exec= action (GNU tar)"),
    CommandOption("tar", "--use-compress-program", "runs the compressor it names"),
    CommandOption("tar", "-I", "runs the compressor it names (GNU tar)"),
    CommandOption("rsync", "-e", "runs the remote shell it names"),
    CommandOption("rsync", "--rsh", "runs the remote shell it names"),
    *(
        CommandOption("find", option, "runs the command that follows", single=False)
        for option in ("-exec", "-execdir", "-ok", "-okdir")
    ),
    *(
        CommandOption(shell, "-c", "runs its value as a shell command", single=False)
        for shell in _SHELLS
    ),
    *(CommandOption(shell, "-o", single=False) for shell in _SHELLS),
    *(
        option
        for shell in _SHELLS
        for option in _flags(shell, *(f"-{letter}" for letter in "abCefhimnsuvx"))
    ),
    *(option for shell in ("bash", "zsh", "ksh") for option in _flags(shell, "-l")),
    CommandOption("python", "-c", "runs its value as Python code"),
    *(
        CommandOption(
            "cmd", option, "runs the rest of the command line as a command", single=False, rest=True
        )
        for option in ("/c", "/C", "/k", "/K")
    ),
    *(
        CommandOption(
            powershell,
            option,
            "runs the rest of the command line as a command",
            single=False,
            rest=True,
        )
        for powershell in ("powershell", "pwsh")
        for option in ("-Command", "-command", "-c", "-EncodedCommand", "-e")
    ),
    *_flags(
        "rm",
        "-d",
        "-f",
        "-I",
        "-i",
        "-R",
        "-r",
        "-v",
        "--dir",
        "--force",
        "--recursive",
        "--verbose",
    ),
)
# Programs documented to read ``--`` as the end of their options.
END_OF_OPTIONS = frozenset({"git", "tar", "rsync", "rm"})
# Programs whose operands, from the given one on, are a command they run, and how.
COMMAND_OPERANDS: Mapping[str, tuple[int, str]] = {
    "ssh": (1, "is part of the command the remote shell runs"),
    "timeout": (1, "may name the program timeout runs"),
    **{
        wrapper: (0, f"may name the program {wrapper} runs")
        for wrapper in ("sudo", "doas", "env", "xargs", "nohup", "nice", "time")
    },
}
# Windows runs a batch file through cmd.exe, which parses its arguments again.
_BATCH = (".bat", ".cmd")

_PROCESS_STARTERS = frozenset(
    SymbolId(f"python.subprocess.{name}")
    for name in ("run", "call", "check_call", "check_output", "Popen")
)
# ``Popen(args, bufsize, executable, ..., shell, ...)``: the other starters pass their
# positional arguments to it.
_COMMAND_ARGUMENT = frozenset({(0, None), (None, "args")})
_EXECUTABLE, _SHELL_POSITION = 2, 8
_SHELL, _NO_SHELL = frozenset({"True", "1"}), frozenset({"False", "None", "0"})
_PYTHON = re.compile(r"python[0-9.]*")
_PYTHON_EXECUTABLE = SymbolId("python.sys.executable")


@dataclass(frozen=True)
class _Reading:
    """What one tainted element of a command lets the attacker do: run a ``command``
    (the program, ``high``), give an option at ``severity``, possibly only ``to_review``,
    or nothing, with ``severity`` None."""

    reason: str
    severity: Severity | None
    command: bool = False
    to_review: bool = False


class CommandInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "command-injection"
    rule_id: ClassVar[str] = "command-injection"
    kind: ClassVar[TaintKind] = TaintKind.COMMAND
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Command injection"
    requires: ClassVar[frozenset[AnyAnalysis]] = TaintDetector.requires | {
        SSAAnalysis,
        DefUseAnalysis,
        ModuleStringsAnalysis,
    }

    def assess(
        self, ctx: PluginContext, function: nodes.Function, flow: TaintFlow, verdict: Verdict
    ) -> Assessment:
        default = super().assess(ctx, function, flow, verdict)
        if flow.sink.symbol not in _PROCESS_STARTERS or flow.through is not None:
            return default
        arguments = flow.sink_arguments
        if arguments is None or not flow.passed_as or not flow.passed_as <= _COMMAND_ARGUMENT:
            return default
        shell = _shell(arguments)
        if shell is True:
            return default
        if shell is None:
            reason = "an expression chooses whether a shell runs the command"
            return Assessment(_to_review(default.verdict, reason), Severity.HIGH)
        ssa = ctx.get(SSAAnalysis, function)
        defs = {
            i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None
        }
        parts = command_parts(flow.argument, defs, ctx.get(DefUseAnalysis, function))
        if parts is None:
            return default
        taint = ctx.get(TaintAnalysis, function)
        command = _Command(parts, defs, ctx.get(ModuleStringsAnalysis), _executable(arguments))
        readings = [
            command.read(index)
            for index, part in enumerate(parts)
            if flow.source in taint.taint(part.value).sources
            and taint.taint(part.value).kinds & TaintKind.COMMAND
        ]
        if not readings or any(reading.command for reading in readings):
            return default
        injected = [reading for reading in readings if reading.severity is not None]
        if not injected:
            return Assessment(
                Verdict(flow, Status.REFUTED, "; ".join(r.reason for r in readings)), self.severity
            )
        severity = max(
            (reading.severity for reading in injected if reading.severity is not None),
            key=lambda found: found.rank,
        )
        decisive = [r for r in injected if r.severity is severity]
        established = [reading for reading in decisive if not reading.to_review]
        if not established:
            return Assessment(_to_review(default.verdict, decisive[0].reason), severity)
        return Assessment(_explained(default.verdict, established[0].reason), severity)


class _Command:
    """The command of one call, read element by element."""

    def __init__(
        self,
        parts: tuple[CommandPart, ...],
        defs: Mapping[Value, Instruction],
        strings: Mapping[str, str],
        executable: str | None,
    ) -> None:
        self.parts = parts
        self.defs = defs
        self.strings = strings
        first = executable if executable is not None else self.text(0)
        made = defs.get(parts[0].value) if parts and parts[0].known else None
        if first is None and isinstance(made, Symbol) and made.symbol_id == _PYTHON_EXECUTABLE:
            first = "python"
        name = re.split(r"[\\/]", first)[-1].lower() if first is not None else None
        self.batch = name is not None and name.endswith(_BATCH)
        if name is not None and name.endswith(".exe"):
            name = name.removesuffix(".exe")
        self.program = "python" if name is not None and _PYTHON.fullmatch(name) else name

    def text(self, index: int) -> str | None:
        """The constant text of the element at ``index``, when all of it is constant."""

        part = self.parts[index]
        if not part.known:
            return None
        text, whole = leading_text(part.value, self.defs, self.strings)
        return text if whole else None

    def read(self, index: int) -> _Reading:
        """What the input at ``index`` lets the attacker do. An element an established
        option takes is judged by what the option does with it, whatever its prefix; one
        that stands alone by what it can still be: the program, a command operand, an
        option, or an operand only."""

        if all(not earlier.known for earlier in self.parts[:index]):
            return _Reading("the input may name the program", Severity.HIGH, command=True)
        if self.batch:
            return _Reading(
                "cmd.exe parses the arguments of a batch file again", Severity.HIGH, command=True
            )
        for position in range(1, index):
            option = self.option(self.text(position) or "", position)
            if option is not None and option.rest:
                return _Reading(
                    f"the input follows {self.program} {option.option}, which {option.runs}",
                    Severity.HIGH,
                )
        before = self.text(index - 1)
        if before is not None and before not in ("-", "--") and self.option_like(before):
            taker = self.taker(before, index)
            if isinstance(taker, CommandOption):
                return self.value_of(taker, before)
            if taker is None:
                if self.command_operand(index) is not False:
                    return self.operand_command()
                free = self.free(index, "the input is a whole element")
                return _Reading(
                    f"cannot tell whether {before} takes the input as its value; if not, {free.reason}",
                    free.severity,
                    to_review=True,
                )
        part = self.parts[index]
        prefix = leading_text(part.value, self.defs, self.strings)[0] if part.known else ""
        if not prefix.startswith("-") and self.command_operand(index) is not False:
            return self.operand_command()
        if not part.known:
            return self.free(index, "the input gives whole elements")
        if prefix.startswith("--") and "=" in prefix:
            return self.option_value(index, prefix[: prefix.index("=")])
        if prefix.startswith("-") and len(prefix) >= 2 and prefix[1] != "-":
            return self.option_value(index, prefix[:2])
        if prefix.startswith("-"):
            return self.free(index, f"the input completes the option {prefix!r}")
        if prefix:
            return _Reading(
                f"the constant prefix {prefix!r} keeps the input from being an option", None
            )
        if self.after_end_of_options(index):
            if self.program in END_OF_OPTIONS:
                return _Reading(f"{self.program} reads the input after '--' as an operand", None)
            return self.free(
                index, "the input follows '--', which the program is not known to honour"
            )
        return self.free(index, "the input is a whole element")

    def option_like(self, text: str) -> bool:
        return text.startswith("-") or any(
            option.option == text for option in OPTIONS if option.program == self.program
        )

    def free(self, index: int, how: str) -> _Reading:
        """An element the attacker may give as an option: ``high`` when an established
        option of the program fits in one element there."""

        dangerous = [
            option for option in self.applicable(index) if option.runs is not None and option.single
        ]
        if dangerous:
            option = dangerous[0]
            return _Reading(
                f"{how}, and an option such as {self.program} {_spelled(option.option)} {option.runs}",
                Severity.HIGH,
            )
        return _Reading(f"{how}, so it may be read as an option", Severity.MEDIUM)

    def option_value(self, index: int, name: str) -> _Reading:
        """The element starts with the option ``name`` and goes on with the input."""

        option = self.option(name, index)
        if option is None:
            return _Reading(f"the input is the value of the option {name}", Severity.MEDIUM)
        if not option.takes_value:
            return self.free(
                index, f"the input follows {name}, which takes no value, as more options"
            )
        return self.value_of(option, name)

    def value_of(self, option: CommandOption, given: str) -> _Reading:
        if option.runs is not None:
            return _Reading(
                f"the input is the value of {self.program} {given}, which {option.runs}",
                Severity.HIGH,
            )
        if option.inert is not None:
            return _Reading(
                f"the input is the value of {self.program} {given}, which {option.inert}", None
            )
        return _Reading(f"the input is the value of {self.program} {given}", Severity.MEDIUM)

    def operand_command(self) -> _Reading:
        assert self.program is not None
        return _Reading(
            f"the input {COMMAND_OPERANDS[self.program][1]}", Severity.HIGH, command=True
        )

    def command_operand(self, index: int) -> bool | None:
        """Whether the element at ``index`` is one of the operands the program runs as a
        command: False when the program has none or the element comes before them, None
        when the options before it do not tell."""

        if self.program not in COMMAND_OPERANDS:
            return False
        operands = self.operands_before(index)
        return None if operands is None else operands >= COMMAND_OPERANDS[self.program][0]

    def operands_before(self, index: int) -> int | None:
        """The number of operands before ``index``, or None when an element of unknown
        value, or an option that may take one, comes first."""

        count, position = 0, 1
        while position < index:
            text = self.text(position)
            if text is None:
                return None
            if text == "--":
                return count + index - position - 1
            if text.startswith("-") and text != "-":
                if not (text.startswith("--") and "=" in text):
                    taker = self.taker(text, position + 1)
                    if taker is None:
                        return None
                    if isinstance(taker, CommandOption):
                        position += 1
            else:
                count += 1
            position += 1
        return count

    def after_end_of_options(self, index: int) -> bool:
        return any(self.text(position) == "--" for position in range(1, index))

    def taker(self, before: str, index: int) -> CommandOption | bool | None:
        """The option ``before`` whose value is the element at ``index``; False when the
        model establishes that ``before`` takes no value there, None when it cannot tell.
        Short options grouped in one element (``-rf``) are read as getopt reads them: the
        first that takes a value takes the rest of the element, or the next element."""

        option = self.option(before, index)
        if option is not None:
            return option if option.takes_value else False
        if not before.startswith("-") or before.startswith("--") or len(before) <= 2:
            return None
        letters = before[1:]
        for position, letter in enumerate(letters):
            option = self.option(f"-{letter}", index)
            if option is None:
                return None
            if option.takes_value:
                return option if position == len(letters) - 1 else False
        return False

    def option(self, name: str, index: int) -> CommandOption | None:
        return next((option for option in self.applicable(index) if option.option == name), None)

    def applicable(self, index: int) -> list[CommandOption]:
        """The options of ``OPTIONS`` the element at ``index`` may give: those of the
        program, after their subcommand when the command shows it before the element, or
        whatever the subcommand when the command does not tell."""

        if self.program is None:
            return []
        subcommand = self.subcommand(index)
        return [
            option
            for option in OPTIONS
            if option.program == self.program
            and (not option.subcommands or subcommand is None or subcommand in option.subcommands)
        ]

    def subcommand(self, index: int) -> str | None:
        """The first operand before ``index``, ``""`` when there is none, or None when an
        element of unknown value, or an option that may take one, comes first."""

        for position in range(1, index):
            text = self.text(position)
            if text is None or text.startswith("-"):
                return None
            return text
        return ""


def _spelled(option: str) -> str:
    """An option with its value in the same element: ``--name=...`` or ``-o...``."""

    return f"{option}=..." if option.startswith("--") else f"{option}..."


def _executable(arguments: Arguments) -> str | None:
    """The program a constant ``executable`` names, which the command's first element
    then only labels."""

    given = arguments.given("executable", _EXECUTABLE)
    written = given[1] if given is not None else None
    if written is None or len(written) < 2 or written[0] not in "'\"" or written[-1] != written[0]:
        return None
    return written[1:-1].replace("\\\\", "\\")


def _shell(arguments: Arguments) -> bool | None:
    """Whether a shell runs the command: True or False when the call says so with a
    constant, by keyword or at its place, None when an expression or unpacked arguments
    decide."""

    given = arguments.given("shell", _SHELL_POSITION)
    if given is None:
        return None
    present, value = given
    if not present:
        return False
    if value in _SHELL:
        return True
    return False if value in _NO_SHELL else None


def _explained(verdict: Verdict, reason: str) -> Verdict:
    """``verdict`` with what the command lets the attacker do added to its evidence."""

    return Verdict(verdict.flow, verdict.status, f"{verdict.evidence}; {reason}")


def _to_review(verdict: Verdict, reason: str) -> Verdict:
    """A finding kept for review: a hotspot whose evidence says why, at most."""

    status = Status.HOTSPOT if verdict.status is Status.VULNERABILITY else verdict.status
    return Verdict(verdict.flow, status, f"{verdict.evidence}; {reason}")
