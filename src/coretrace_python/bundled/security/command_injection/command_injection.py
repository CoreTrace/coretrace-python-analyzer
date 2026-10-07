"""Command injection: attacker-controlled input reaching a COMMAND sink.

What decides the result is what the attacker still controls in the command a process is
started with (issue #208). A string that a shell interprets, a string naming the program,
the program itself, or an operand that the program runs as shell text (``ssh`` after the
host, a shell's first operand after ``-c``, any argument of a batch file) is a command
injection, ``high``. Operands that are a command of their own (the program a wrapper such
as ``sudo`` runs, what follows ``find -exec``) are read again as that command. The script
an interpreter runs (its first operand when no option gives the code, as ``bash run.sh`` or
``python tool.py``), or the module ``python -m`` runs, is ``high`` to review: execution is
possible, and whether it is exploitable depends on the file the input chooses. The
arguments that follow a script or code are the script's: its own options, whose meaning is
unknown, kept for review after an option and refuted behind a constant prefix. An element
of an argument list run without a shell otherwise injects at most an option: ``medium``,
or ``high`` when ``OPTIONS`` establishes that the program runs a command chosen through an
option that fits there.

A value an option takes is judged by what ``OPTIONS`` establishes the option does with
it, whatever its prefix: run it (``cmd /c``, ``python -c``: ``high``), keep it as data
(``git commit -m``: refuted), or something not established (``medium``). After an option
``OPTIONS`` does not describe, or an element of unknown value, the finding is kept for
review at the severity of a free element; after options established to take no value
(``rm -rf``, grouped short options read as getopt reads them), the element stands alone.
An element standing alone is judged by its constant prefix: ``f"v{x}"`` is no option, the
value of ``f"--output={x}"`` belongs to a fixed option, ``f"--{x}"`` leaves the option
open. A ``hotspot`` verdict lowers the confidence, never the severity, which each case
sets.
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
from coretrace_python.ir.model import Call, Instruction, Symbol, Value
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
    and its value; with ``rest``, every element after it is its value, and with ``opens``
    the elements after it, up to ``;`` or ``+``, are a command of their own. What the
    program does with the value decides: with ``runs``, it runs a command the value
    chooses (``examine``: a choice among code already there, such as a module, whose
    exploitability is to examine); with ``inert``, it only keeps it as data (a commit
    message); with neither, the effect is not established. An option that takes no value leaves the next element
    free."""

    program: str
    option: str
    runs: str | None = None
    subcommands: tuple[str, ...] = ()
    single: bool = True
    takes_value: bool = True
    inert: str | None = None
    rest: bool = False
    opens: bool = False
    examine: bool = False

    def __post_init__(self) -> None:
        if self.rest and not self.takes_value:
            raise ValueError(f"{self.program} {self.option}: a rest option takes the elements after it")


@dataclass(frozen=True)
class CommandOperands:
    """Operands a program runs, counted from 0 after its options, of one ``kind``: from
    operand ``first`` on, shell ``text`` the program has a shell run, or a ``command`` of
    its own (a program and its arguments); or operand ``first`` only, a ``script`` file
    the program runs, whose contents decide what runs. With ``after``, only when one of
    those options comes before the operands, and then operand ``first`` only (``sh -c
    'cmd' name arguments``); with ``unless``, only when none of them does (``python -c``
    gives the code, not a script). With ``assignments``, ``NAME=VALUE`` operands before
    the program set its environment and do not count (``env A=1 cmd``)."""

    first: int
    kind: str
    how: str
    after: tuple[str, ...] = ()
    unless: tuple[str, ...] = ()
    assignments: bool = False


def _flags(program: str, *options: str) -> tuple[CommandOption, ...]:
    return tuple(CommandOption(program, option, takes_value=False) for option in options)


_SHELLS = ("sh", "bash", "dash", "zsh", "ksh")
_WRAPPERS = ("sudo", "doas", "env", "xargs", "nohup", "nice", "time")

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
            ("-u", ("clone", "ls-remote")),
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
        CommandOption("find", option, "runs the command that follows", single=False, opens=True)
        for option in ("-exec", "-execdir", "-ok", "-okdir")
    ),
    *(CommandOption(shell, sign + "o", single=False) for shell in _SHELLS for sign in "-+"),
    *(
        option
        for shell in _SHELLS
        for option in _flags(shell, *(f"+{letter}" for letter in "abCefhmnuvx"))
    ),
    *_flags(
        "bash",
        "--login",
        "--noediting",
        "--noprofile",
        "--norc",
        "--posix",
        "--restricted",
        "--verbose",
    ),
    *(CommandOption("bash", option, single=False) for option in ("--rcfile", "--init-file")),
    *(
        option
        for shell in _SHELLS
        for option in _flags(shell, *(f"-{letter}" for letter in "abCcefhilmnsuvx"))
    ),
    CommandOption("python", "-c", "runs its value as Python code"),
    CommandOption("python", "-m", "runs the module it names", examine=True),
    CommandOption("python", "-W", "imports the module its warning category names", examine=True),
    CommandOption("python", "-X", single=False),
    *_flags("python", *(f"-{letter}" for letter in "23bBdEhiIOPqsSuvVx")),
    *_flags("perl", *(f"-{letter}" for letter in "acnpsStTUwWX")),
    CommandOption("perl", "-I", single=True),
    *_flags("ruby", *(f"-{letter}" for letter in "acdlnpsvwWy")),
    *(CommandOption("ruby", option) for option in ("-I", "-C", "-E")),
    *_flags(
        "node",
        "-c",
        "--check",
        "-i",
        "--interactive",
        "--inspect",
        "--inspect-brk",
        "--no-warnings",
        "--no-deprecation",
        "--trace-warnings",
        "--enable-source-maps",
        "--expose-gc",
        "--preserve-symlinks",
    ),
    *_flags("php", *(f"-{letter}" for letter in "aehHilmnqsvw")),
    CommandOption("php", "-f", "runs the script it names", examine=True),
    CommandOption("php", "-d", "sets any ini directive, auto_prepend_file included", examine=True),
    CommandOption("php", "-c", "loads the php.ini it names", examine=True),
    CommandOption("php", "-z", "loads the Zend extension it names", examine=True),
    *(CommandOption("perl", option, "runs its value as Perl code") for option in ("-e", "-E")),
    *(
        CommandOption("perl", option, "runs the import of its value as Perl code")
        for option in ("-M", "-m")
    ),
    CommandOption("ruby", "-e", "runs its value as Ruby code"),
    CommandOption("ruby", "-r", "requires the library it names", examine=True),
    # node reads the value of a short option from the next element only.
    *(
        CommandOption(
            "node",
            option,
            "loads the module it names",
            examine=True,
            single=option.startswith("--"),
        )
        for option in ("-r", "--require", "--import")
    ),
    *(
        CommandOption(
            "node", option, "runs its value as JavaScript code", single=option.startswith("--")
        )
        for option in ("-e", "--eval", "-p", "--print", "-pe")
    ),
    *(
        CommandOption("php", option, "runs its value as PHP code")
        for option in ("-r", "-B", "-R", "-E")
    ),
    *(
        CommandOption(
            "cmd", option, "runs the rest of the command line as a command", single=False, rest=True
        )
        for option in ("/c", "/k")
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
        for option in ("-command", "-c", "-encodedcommand", "-e", "-ec")
    ),
    *(
        option
        for powershell in ("powershell", "pwsh")
        for option in (
            CommandOption(
                powershell, "-file", "runs the script it names", single=False, examine=True
            ),
            *_flags(
                powershell, "-noprofile", "-noninteractive", "-nologo", "-noexit", "-sta", "-mta"
            ),
            *(
                CommandOption(powershell, value, single=False)
                for value in ("-executionpolicy", "-windowstyle", "-inputformat", "-outputformat")
            ),
        )
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
# Interpreters run the script their first operand names, unless one of these options
# gives the code or the script instead (or, for a shell's ``-s``, reads it from the
# standard input).
_POWERSHELL_CODE = ("-command", "-c", "-encodedcommand", "-e", "-ec", "-file")
_SCRIPTS: Mapping[str, tuple[str, ...]] = {
    **{shell: ("-c", "-s") for shell in _SHELLS},
    "python": ("-c", "-m"),
    "perl": ("-e", "-E"),
    "ruby": ("-e",),
    "node": ("-e", "--eval", "-p", "--print", "-pe"),
    "php": ("-r", "-f", "-B", "-R", "-E"),
    "pwsh": _POWERSHELL_CODE,
}
# These read their options after the code too, up to their first operand: what follows
# ``perl -e CODE`` may be another ``-e``. Python and the shells read none after it.
_OPTIONS_AFTER_CODE = frozenset({"perl", "ruby", "node", "php"})


def _interpreter(name: str, code: tuple[str, ...]) -> tuple[CommandOperands, ...]:
    script = CommandOperands(0, "script", f"names the script {name} runs", unless=code)
    if name not in _SHELLS:
        return (script,)
    return (
        CommandOperands(0, "text", "is the command the shell runs after -c", after=("-c",)),
        script,
    )


OPERANDS: Mapping[str, tuple[CommandOperands, ...]] = {
    "ssh": (CommandOperands(1, "text", "is part of the command the remote shell runs"),),
    "powershell": (
        CommandOperands(0, "text", "is part of the command PowerShell runs", unless=("-file",)),
    ),
    "timeout": (CommandOperands(1, "command", "names the program timeout runs"),),
    **{
        wrapper: (
            CommandOperands(
                0,
                "command",
                f"names the program {wrapper} runs",
                assignments=wrapper in ("env", "sudo"),
            ),
        )
        for wrapper in _WRAPPERS
    },
    **{interpreter: _interpreter(interpreter, code) for interpreter, code in _SCRIPTS.items()},
}
# Windows runs a batch file through cmd.exe, which parses its arguments again; its own
# programs read their options whatever the case.
_BATCH = (".bat", ".cmd")
_ANY_CASE = frozenset({"cmd", "powershell", "pwsh"})
_TERMINATORS = (";", "+")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_WHICH = SymbolId("python.shutil.which")
# Commands inside commands are read to this depth; deeper, an element is taken to be an
# operand the program runs.
_MAX_DEPTH = 32

_PROCESS_STARTERS = frozenset(
    SymbolId(f"python.subprocess.{name}")
    for name in ("run", "call", "check_call", "check_output", "Popen")
)
# ``Popen(args, bufsize, executable, ..., shell, ...)``: the other starters pass their
# positional arguments to it.
_COMMAND_ARGUMENT = frozenset({(0, None), (None, "args")})
_EXECUTABLE, _SHELL_POSITION = 2, 8
_SHELL, _NO_SHELL = frozenset({"True", "1"}), frozenset({"False", "None", "0"})
# Versioned and distribution names of interpreters: python3.12, pythonw, python3-dbg,
# pypy3, the Windows launchers py and pyw, nodejs, perl5.36, ruby3.2, php8.2.
_INTERPRETER = re.compile(r"(python|pypy|perl|ruby|php|node|py)(?:js)?[0-9.]*w?(?:-dbg)?")
_PYTHON_EXECUTABLE = SymbolId("python.sys.executable")


@dataclass(frozen=True)
class _Reading:
    """What one tainted element of a command lets the attacker do: run a ``command``
    (``high``), give an option at ``severity``, possibly only ``to_review``, or nothing,
    with ``severity`` None."""

    reason: str
    severity: Severity | None
    command: bool = False
    to_review: bool = False


@dataclass(frozen=True)
class _Operands:
    """The operands before an element, by position; whether the option before it takes
    the element as its value (``consumed``); whether a ``--`` ended the options."""

    positions: tuple[int, ...]
    consumed: bool = False
    ended: bool = False


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
        if not parts:
            return default
        taint = ctx.get(TaintAnalysis, function)
        command = _Command(
            parts, defs, ctx.get(ModuleStringsAnalysis), _program(arguments, parts[0], defs)
        )
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
    """A command, read element by element; ``program`` is the name of the program it
    runs, None when unknown."""

    def __init__(
        self,
        parts: tuple[CommandPart, ...],
        defs: Mapping[Value, Instruction],
        strings: Mapping[str, str],
        program: str | None,
        depth: int = 0,
    ) -> None:
        self.parts = parts
        self.defs = defs
        self.strings = strings
        self.depth = depth
        name = _name(program) if program is not None else None
        self.batch = name is not None and name.endswith(_BATCH)
        self.program = name
        # Each element's text, and the options by subcommand, are read once: ``read``
        # looks back over the command for every tainted element.
        self._texts: dict[int, str | None] = {}
        self._options: dict[str | None, list[CommandOption]] = {}

    def nested(self, start: int, end: int | None = None) -> _Command:
        """The command that the elements from ``start`` (to ``end``) spell."""

        parts = self.parts[start:end]
        program = _first_program(parts[0], self.defs, self.strings)
        return _Command(parts, self.defs, self.strings, program, self.depth + 1)

    def text(self, index: int) -> str | None:
        """The constant text of the element at ``index``, when all of it is constant."""

        if index not in self._texts:
            part = self.parts[index]
            text, whole = (
                leading_text(part.value, self.defs, self.strings) if part.known else ("", False)
            )
            self._texts[index] = text if whole else None
        return self._texts[index]

    def prefix(self, index: int) -> str:
        part = self.parts[index]
        return leading_text(part.value, self.defs, self.strings)[0] if part.known else ""

    def read(self, index: int) -> _Reading:
        """What the input at ``index`` lets the attacker do. Operands the program runs
        come first; then an element an established option takes is judged by what the
        option does with it, whatever its prefix; one standing alone, by what it can
        still be: an option, or an operand only."""

        if all(not earlier.known for earlier in self.parts[:index]):
            return _Reading("the input may name the program", Severity.HIGH, command=True)
        if self.batch:
            return _Reading(
                "cmd.exe parses the arguments of a batch file again", Severity.HIGH, command=True
            )
        operand = self.operand(index)
        if operand is not None:
            return operand
        if self.program is None:
            free = self.free(index, "the input is an element")
            return self.review(
                f"the program is unknown and may run its operands; {free.reason}", free
            )
        for position in range(1, index):
            option = self.option(self.text(position) or "", position)
            if option is not None and option.opens:
                end = next(
                    (
                        later
                        for later in range(position + 1, len(self.parts))
                        if self.text(later) in _TERMINATORS
                    ),
                    len(self.parts),
                )
                if position < index < end:
                    return self.inside(position + 1, end, index)
            if option is not None and option.rest:
                return _Reading(
                    f"the input follows {self.program} {option.option}, which {option.runs}",
                    Severity.HIGH,
                )
        if index >= 2:
            before = self.text(index - 1)
            if before is None:
                free = self.free(index, "the input is a whole element")
                return self.review(
                    f"cannot tell what the element before the input is; if not an option, {free.reason}",
                    free,
                )
            if before not in ("-", "--") and self.option_like(before):
                taker = self.taker(before, index)
                if isinstance(taker, CommandOption):
                    if not self.parts[index].known and taker.runs is None:
                        return self.free(index, f"the input gives whole elements after {before}")
                    return self.value_of(taker, before)
                if taker is None:
                    free = self.free(index, "the input is a whole element")
                    return self.review(
                        f"cannot tell whether {before} takes the input as its value; if not, {free.reason}",
                        free,
                    )
        if not self.parts[index].known:
            return self.free(index, "the input gives whole elements")
        prefix = self.prefix(index)
        for option in self.applicable(index):
            if option.rest and self.same(prefix[: len(option.option)], option.option):
                return _Reading(
                    f"the input follows {self.program} {option.option}, which {option.runs}",
                    Severity.HIGH,
                )
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
        if any(self.text(position) == "--" for position in range(1, index)):
            if self.program in END_OF_OPTIONS:
                return _Reading(f"{self.program} reads the input after '--' as an operand", None)
            return self.free(
                index, "the input follows '--', which the program is not known to honour"
            )
        return self.free(index, "the input is a whole element")

    def operand(self, index: int) -> _Reading | None:
        """The reading of an element among the operands the program runs, or None when
        the element is not one of them."""

        for spec in OPERANDS.get(self.program or "", ()):
            reading = self.operand_of(spec, index)
            if reading is not None:
                return reading
        return None

    def operand_of(self, spec: CommandOperands, index: int) -> _Reading | None:
        script = spec.kind == "script"
        unclear = _Reading(
            f"the input may be an operand that {spec.how}",
            Severity.HIGH,
            command=not script,
            to_review=script,
        )
        if spec.after:
            given = self.given(spec.after, index)
            if given is None:
                return unclear
            if given is False:
                return None
        if spec.unless:
            given = self.given(spec.unless, index)
            if given is None:
                return unclear
            if given is not False:
                return self.after_code(given, index)
        operands = self.operands(index, spec.first + 1, spec.assignments)
        if operands is None:
            return unclear
        if operands.consumed:
            return None
        count = len(operands.positions)
        operand_like = operands.ended or not self.prefix(index).startswith("-")
        if count > spec.first:
            if spec.kind == "command":
                return self.inside(operands.positions[spec.first], None, index)
            if spec.kind == "text" and not spec.after:
                return _Reading(f"the input {spec.how}", Severity.HIGH, command=True)
            return self.argument(operands.positions[spec.first] + 1, index)
        if count == spec.first and operand_like:
            if not script:
                return _Reading(f"the input {spec.how}", Severity.HIGH, command=True)
            if not operands.ended and self.prefix(index) == "":
                # A whole element there may as well be a code option and its value.
                free = self.free(index, "the input is a whole element")
                if free.severity is Severity.HIGH:
                    return free
            return _Reading(
                f"the input {spec.how}, whose contents decide what runs",
                Severity.HIGH,
                to_review=True,
            )
        return None

    def argument(self, start: int, index: int) -> _Reading:
        """An argument of a script or of code given by an option, the arguments starting at
        ``start``, which the engine does not read: an option of it, whose meaning is
        unknown, unless a constant prefix keeps it from being one."""

        before = self.text(index - 1) if index > start else None
        if (
            before is not None
            and before.startswith("-")
            and before not in ("-", "--")
            and "=" not in before
        ):
            return _Reading(
                f"the input follows {before}, an option of the script it may be the value of",
                Severity.MEDIUM,
                to_review=True,
            )
        prefix = self.prefix(index)
        if self.parts[index].known and prefix and not prefix.startswith("-"):
            return _Reading(
                f"the input is an argument of the script, behind the constant prefix {prefix!r}",
                None,
            )
        return _Reading(
            "the input is an argument of the script, which it may read as an option",
            Severity.MEDIUM,
        )

    def inside(self, start: int, end: int | None, index: int) -> _Reading:
        """The reading of the element at ``index`` in the command the elements from
        ``start`` (to ``end``) spell, which the program runs."""

        if index == start:
            return _Reading(
                f"the input names the program {self.program} runs", Severity.HIGH, command=True
            )
        if self.depth >= _MAX_DEPTH:
            return _Reading(
                f"the input is in a command {self.program} runs", Severity.HIGH, command=True
            )
        reading = self.nested(start, end).read(index - start)
        return _Reading(
            f"in the command {self.program} runs, {reading.reason}",
            reading.severity,
            reading.command,
            reading.to_review,
        )

    def operands(self, index: int, enough: int, assignments: bool = False) -> _Operands | None:
        """The operands before ``index``, up to ``enough`` of them, without ``NAME=VALUE``
        assignments when the program reads them; None when an element of unknown value, or
        an option that may take one, comes first."""

        positions: list[int] = []
        position = 1
        while position < index and len(positions) < enough:
            text = self.text(position)
            if text is None:
                return None
            if text == "--" or (text == "-" and self.program in _SHELLS):
                return _Operands((*positions, *range(position + 1, index))[:enough], ended=True)
            if self.option_like(text) and text != "-":
                if not (text.startswith("--") and "=" in text):
                    taker = self.taker(text, position + 1)
                    if taker is None:
                        return None
                    if isinstance(taker, CommandOption):
                        position += 1
                        if position == index:
                            return _Operands(tuple(positions), consumed=True)
            elif not (assignments and _ASSIGNMENT.match(text)):
                positions.append(position)
            position += 1
        return _Operands(tuple(positions))

    def given(self, names: tuple[str, ...], index: int) -> int | bool | None:
        """Where one of the options ``names`` ends among the options before ``index``: the
        position of the element holding its value, or of the option itself when it takes
        none; False when none comes, None when an element of unknown value, or an option
        that may take one, comes first. Options are read as getopt reads them: a short
        option that takes a value takes the rest of its element."""

        position = 1
        while position < index:
            text = self.text(position)
            if text is None:
                return None
            if text == "--" or text in ("-", "+") or not self.option_like(text):
                return False
            whole = text.split("=", 1)[0]
            if self.named(whole, names):
                option = self.option(text, position + 1)
                return (
                    position + 1
                    if "=" not in text and option is not None and option.takes_value
                    else position
                )
            grouped = text[0] in "-+" and not text.startswith("--") and len(text) > 2
            if grouped and self.option(whole, position + 1) is None:
                for offset, letter in enumerate(text[1:], start=1):
                    option = self.option(text[0] + letter, position + 1)
                    last = offset == len(text) - 1
                    if self.named(text[0] + letter, names):
                        return (
                            position + 1
                            if last and option is not None and option.takes_value
                            else position
                        )
                    if option is None:
                        return None
                    if option.takes_value:
                        position += last
                        break
            elif not (text.startswith("--") and "=" in text):
                taker = self.taker(text, position + 1)
                if taker is None:
                    return None
                position += isinstance(taker, CommandOption)
            position += 1
        return False

    def after_code(self, given: int, index: int) -> _Reading | None:
        """The reading of the element at ``index``, once the option ending at ``given`` gave
        the code: an argument of it, except that the interpreters of
        ``_OPTIONS_AFTER_CODE`` read options up to their first operand, which the usual
        reading of options judges (None)."""

        if index <= given:
            return None
        # Not ``given`` itself: it holds the value of the code option (the script after
        # ``pwsh -File``, whatever it is spelled like), or that option when it takes no
        # value, which is then no ``rest`` option, since every element after one is its value.
        for position in range(1, given):
            option = self.option(self.text(position) or "", position)
            if option is not None and option.rest:
                # Every element after it is the command (``pwsh -Command``).
                return None
        if self.program not in _OPTIONS_AFTER_CODE:
            return self.argument(given + 1, index)
        operands = self.operands(index, 1)
        if operands is None or operands.consumed:
            return None
        if operands.positions:
            return self.argument(operands.positions[0], index)
        prefix = self.prefix(index)
        if operands.ended or (prefix and not prefix.startswith("-")):
            return self.argument(index, index)
        if prefix.startswith("-"):
            return None
        return self.free(index, "the input is a whole element where options are still read")

    def named(self, written: str, names: tuple[str, ...]) -> bool:
        return any(self.same(written, name) for name in names)

    def review(self, reason: str, free: _Reading) -> _Reading:
        return _Reading(reason, free.severity, to_review=True)

    def same(self, written: str, option: str) -> bool:
        return written.lower() == option.lower() if self.program in _ANY_CASE else written == option

    def option_like(self, text: str) -> bool:
        """Whether ``text`` reads as an option of the program: ``-x``, a shell's ``+x``, or
        an option the model names (``/c``)."""

        if text.startswith("-") or (
            self.program in _SHELLS and text.startswith("+") and text != "+"
        ):
            return True
        return any(
            self.same(text, option.option) for option in OPTIONS if option.program == self.program
        )

    def free(self, index: int, how: str) -> _Reading:
        """An element the attacker may give as an option: ``high`` when an established
        option of the program fits in one element there."""

        dangerous = [
            option for option in self.applicable(index) if option.runs is not None and option.single
        ]
        if dangerous:
            option = min(dangerous, key=lambda found: found.examine)
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
        if option.runs is not None and option.examine:
            return _Reading(
                f"the input is the value of {self.program} {given}, which {option.runs}",
                Severity.HIGH,
                to_review=True,
            )
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

    def taker(self, before: str, index: int) -> CommandOption | bool | None:
        """The option ``before`` whose value is the element at ``index``; False when the
        model establishes that ``before`` takes no value there, None when it cannot tell.
        Short options grouped in one element (``-rf``) are read as getopt reads them: the
        first that takes a value takes the rest of the element, or the next element."""

        option = self.option(before, index)
        if option is not None:
            return option if option.takes_value else False
        sign = before[:1]
        if sign not in ("-", "+") or before.startswith("--") or len(before) <= 2:
            return None
        letters = before[1:]
        for position, letter in enumerate(letters):
            option = self.option(f"{sign}{letter}", index)
            if option is None:
                return None
            if option.takes_value:
                return option if position == len(letters) - 1 else False
        return False

    def option(self, name: str, index: int) -> CommandOption | None:
        return next(
            (option for option in self.applicable(index) if self.same(name, option.option)), None
        )

    def applicable(self, index: int) -> list[CommandOption]:
        """The options of ``OPTIONS`` the element at ``index`` may give: those of the
        program, after their subcommand when the command shows it before the element. When
        the command does not tell, options that run a command still apply, whatever their
        subcommand, but not an inert reading, which needs the subcommand established."""

        if self.program is None:
            return []
        subcommand = self.subcommand(index)
        if subcommand not in self._options:
            self._options[subcommand] = [
                option
                for option in OPTIONS
                if option.program == self.program
                and (
                    not option.subcommands
                    or (subcommand is None and option.inert is None)
                    or subcommand in option.subcommands
                )
            ]
        return self._options[subcommand]

    def subcommand(self, index: int) -> str | None:
        """The first operand before ``index``, ``""`` when there is none, or None when an
        element of unknown value, or an option that may take one, comes first."""

        for position in range(1, index):
            text = self.text(position)
            if text is None or text.startswith("-"):
                return None
            return text
        return ""


def _name(program: str) -> str:
    """The name a program is known by in ``OPTIONS``: without its directory (POSIX or
    Windows) or ``.exe``, in lower case, an interpreter without its version (``pypy`` and
    the Windows launcher ``py`` as ``python``)."""

    name = re.split(r"[\\/]", program)[-1].lower().removesuffix(".exe")
    interpreter = _INTERPRETER.fullmatch(name)
    if interpreter is not None:
        name = interpreter.group(1)
    return "python" if name in ("pypy", "py") else name


def _first_program(
    part: CommandPart, defs: Mapping[Value, Instruction], strings: Mapping[str, str]
) -> str | None:
    """The program the first element of a command names: its constant text, Python for
    ``sys.executable``, or the name ``shutil.which`` looks up; None when unknown."""

    if not part.known:
        return None
    text, whole = leading_text(part.value, defs, strings)
    if whole:
        return text
    made = defs.get(part.value)
    if isinstance(made, Symbol) and made.symbol_id == _PYTHON_EXECUTABLE:
        return "python"
    if isinstance(made, Call) and made.arguments:
        callee = defs.get(made.callee)
        if isinstance(callee, Symbol) and callee.symbol_id == _WHICH:
            name, whole = leading_text(made.arguments[0], defs, strings)
            return name if whole else None
    return None


def _program(
    arguments: Arguments, first: CommandPart, defs: Mapping[Value, Instruction]
) -> str | None:
    """The program a call runs: the one a constant ``executable`` names, which the
    command's first element then only labels, or the one that element names. An
    ``executable`` that is given but cannot be read leaves the program unknown."""

    given = arguments.given("executable", _EXECUTABLE)
    if given == (False, None):
        return _first_program(first, defs, {})
    written = given[1] if given is not None else None
    if written == str(_PYTHON_EXECUTABLE):
        return "python"
    if written is None or len(written) < 2 or written[0] not in "'\"" or written[-1] != written[0]:
        return None
    return written[1:-1].replace("\\\\", "\\")


def _spelled(option: str) -> str:
    """An option with its value in the same element: ``--name=...`` or ``-o...``."""

    return f"{option}=..." if option.startswith("--") else f"{option}..."


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
