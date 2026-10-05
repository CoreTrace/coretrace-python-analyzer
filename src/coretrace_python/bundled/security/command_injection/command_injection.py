"""Command injection: attacker-controlled input reaching a COMMAND sink.

What decides the result is what the attacker still controls in the command a process is
started with (issue #208). A string that a shell interprets, a string naming the program
or the program itself is a command injection, ``high``. An element of an argument list
run without a shell injects at most an option: ``medium``, or ``high`` when ``OPTIONS``
establishes that the program runs a command chosen through that option. A constant
prefix is judged by what it leaves to the attacker: ``f"v{x}"`` is no option, the value
of ``f"--output={x}"`` belongs to a fixed option, ``f"--{x}"`` leaves the option open.
A value after an option belongs to that option only when ``OPTIONS`` establishes that the
option takes it, and is a free element when ``OPTIONS`` establishes that the options before
it take none (``rm -rf``, read as getopt reads grouped short options); otherwise the
finding is kept for review. A ``hotspot`` verdict lowers
the confidence, never the severity, which each case sets.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import ClassVar

from coretrace_python.abstract.strings import ModuleStringsAnalysis, leading_text
from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.findings.refutation import Status, Verdict
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import Arguments
from coretrace_python.ir.defuse import DefUseAnalysis
from coretrace_python.ir.model import Instruction, Value
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import Assessment, PluginContext, TaintDetector
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TaintAnalysis, TaintFlow, TaintKind
from coretrace_python.taint.commands import CommandPart, command_parts


@dataclass(frozen=True)
class CommandOption:
    """An option of ``program``, after one of ``subcommands`` when any are given. An
    option that ``takes_value`` reads it from the next element, or after ``=`` or the
    short option in the same element; with ``runs``, the program runs a command that
    value chooses (``runs`` says how), and ``single`` says one element can carry the
    option and its value. An option that takes no value leaves the next element free."""

    program: str
    option: str
    runs: str | None = None
    subcommands: tuple[str, ...] = ()
    single: bool = True
    takes_value: bool = True


def _flags(program: str, *options: str) -> tuple[CommandOption, ...]:
    return tuple(CommandOption(program, option, takes_value=False) for option in options)


# Documented behaviours only: an option missing here is neither established to be
# dangerous nor to take no value.
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
    CommandOption("ssh", "-o", "sets options such as ProxyCommand, which runs a command"),
    *_flags("ssh", *(f"-{letter}" for letter in "46AaCfGgKkMNnqsTtVvXxYy")),
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
    CommandOption(
        "tar", "--to-command", "pipes each extracted file to the command it names (GNU tar)"
    ),
    CommandOption("tar", "--checkpoint-action", "runs the command of an exec= action (GNU tar)"),
    CommandOption("tar", "--use-compress-program", "runs the compressor it names"),
    CommandOption("rsync", "-e", "runs the remote shell it names"),
    CommandOption("rsync", "--rsh", "runs the remote shell it names"),
    *(
        CommandOption("find", option, "runs the command that follows", single=False)
        for option in ("-exec", "-execdir", "-ok", "-okdir")
    ),
    *(
        CommandOption(shell, "-c", "runs its value as a shell command", single=False)
        for shell in ("sh", "bash", "dash", "zsh", "ksh")
    ),
    *(
        CommandOption(python, "-c", "runs its value as Python code")
        for python in ("python", "python3")
    ),
)
# Programs documented to read ``--`` as the end of their options.
END_OF_OPTIONS = frozenset({"git", "ssh", "tar", "rsync"})

_PROCESS_STARTERS = frozenset(
    SymbolId(f"python.subprocess.{name}")
    for name in ("run", "call", "check_call", "check_output", "Popen")
)
_COMMAND_ARGUMENT = frozenset({(0, None), (None, "args")})
_SHELL, _NO_SHELL = frozenset({"True", "1"}), frozenset({"False", "None", "0"})


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
        if not flow.passed_as & _COMMAND_ARGUMENT or flow.sink_arguments is None:
            return default
        shell = _shell(flow.sink_arguments)
        if shell is True:
            return default
        if shell is None:
            return Assessment(
                _to_review(
                    default.verdict, "an expression chooses whether a shell runs the command"
                ),
                Severity.HIGH,
            )
        ssa = ctx.get(SSAAnalysis, function)
        defs = {
            i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None
        }
        parts = command_parts(flow.argument, defs, ctx.get(DefUseAnalysis, function))
        if parts is None:
            return default
        taint = ctx.get(TaintAnalysis, function)
        command = _Command(parts, defs, ctx.get(ModuleStringsAnalysis))
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
    ) -> None:
        self.parts = parts
        self.defs = defs
        self.strings = strings
        first = self.text(0)
        self.program = PurePosixPath(first).name if first is not None else None

    def text(self, index: int) -> str | None:
        """The constant text of the element at ``index``, when all of it is constant."""

        part = self.parts[index]
        if not part.known:
            return None
        text, whole = leading_text(part.value, self.defs, self.strings)
        return text if whole else None

    def read(self, index: int) -> _Reading:
        part = self.parts[index]
        if all(not earlier.known for earlier in self.parts[:index]):
            return _Reading("the input may name the program", Severity.HIGH, command=True)
        if not part.known:
            return self.free(index, "the input gives whole elements")
        prefix, _ = leading_text(part.value, self.defs, self.strings)
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
        before = self.text(index - 1)
        if before == "--":
            if self.program in END_OF_OPTIONS:
                return _Reading(f"{self.program} reads the input after '--' as an operand", None)
            return self.free(
                index, "the input follows '--', which the program is not known to honour"
            )
        if before is not None and before.startswith("-") and before != "-" and "=" not in before:
            taker = self.taker(before, index)
            if isinstance(taker, CommandOption):
                return self.value_of(taker, before)
            if taker is False:
                return self.free(
                    index, f"the input is a whole element after {before}, which takes no value"
                )
            free = self.free(index, "the input is a whole element")
            return _Reading(
                f"cannot tell whether {before} takes the input as its value; if not, {free.reason}",
                free.severity,
                to_review=True,
            )
        return self.free(index, "the input is a whole element")

    def free(self, index: int, how: str) -> _Reading:
        """An element the attacker may give as an option: ``high`` when an established
        option of the program fits in one element there."""

        dangerous = [
            option for option in self.applicable(index) if option.runs is not None and option.single
        ]
        if dangerous:
            option = dangerous[0]
            return _Reading(
                f"{how}, and {self.program} {option.option}=... {option.runs}", Severity.HIGH
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
        return _Reading(f"the input is the value of {self.program} {given}", Severity.MEDIUM)

    def taker(self, before: str, index: int) -> CommandOption | bool | None:
        """The option ``before`` whose value is the element at ``index``; False when the
        model establishes that ``before`` takes no value there, None when it cannot tell.
        Short options grouped in one element (``-rf``) are read as getopt reads them: the
        first that takes a value takes the rest of the element, or the next element."""

        option = self.option(before, index)
        if option is not None:
            return option if option.takes_value else False
        if before.startswith("--") or len(before) <= 2:
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


def _shell(arguments: Arguments) -> bool | None:
    """Whether a shell runs the command: True or False when the call says so with a
    constant, None when an expression or unpacked keywords decide."""

    given = arguments.given("shell")
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
