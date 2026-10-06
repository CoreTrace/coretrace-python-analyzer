"""Acceptance tests for issue #208: what the attacker controls in a process's command.

A string that a shell interprets, a string naming the program, or the program itself is
a command injection, ``high``. An element of an argument list run without a shell
cannot inject a command, only an option: ``medium`` by default when the executable is
fixed, ``high`` when the option's dangerous behaviour is established by model data
(``git push --receive-pack=<cmd>``, ``ssh -o ProxyCommand=...``, ``sh -c``). A constant
prefix is judged by what the attacker still controls: ``f"v{x}"`` is no option at all,
``f"--output={x}"`` is the value of a fixed option, ``f"--{x}"`` leaves the option open.
A value an option takes is judged by what the model establishes the option does with it,
whatever its prefix: run it (``sh -c``, ``cmd /c``, ``python -c``: ``high``), keep it as
data (``git commit -m``: refuted), or something not established (``medium``). After an
option the model does not describe, the finding stays for review; after options the model
establishes to take no value (``rm -rf``), the element stands alone. Operands that a
program runs as a command (after the host for ``ssh``, a wrapper's program such as
``sudo``'s, any argument of a batch file) are ``high``. Severity is set per case:
the ``hotspot`` verdict lowers the confidence, never the severity.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.frontend import build_hir
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.model import BuildList, BuildTuple
from coretrace_python.source import SourceManager

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"

HIGH = ("high", "vulnerability", "high")
MEDIUM = ("medium", "vulnerability", "high")
HIGH_TO_REVIEW = ("high", "hotspot", "medium")
MEDIUM_TO_REVIEW = ("medium", "hotspot", "medium")


def judged(call: str) -> list[tuple[str, str, str]]:
    """Severity, verdict and confidence of each command-injection finding on ``call``,
    made with ``x`` read from the command line and ``extra`` of unknown value."""

    text = f"import os\nimport shutil\nimport subprocess\nimport sys\n\n\ndef run(extra):\n    x = sys.argv[1]\n    {call}\n"
    findings = engine.check(SourceManager().add_source("app/run.py", text), [PLUGINS])
    return [
        (f.severity.value, f.metadata["verdict"], f.confidence.value)
        for f in findings
        if f.rule_id == "command-injection"
    ]


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        # 1, 2, 3, 8: the attacker reaches a shell or chooses the program.
        ('subprocess.run(f"git tag {x}", shell=True)', HIGH),
        ('os.system("ls " + x)', HIGH),
        ("subprocess.run(x)", HIGH),
        ('subprocess.run([x, "-l"])', HIGH),
        ('subprocess.run(["ls"], executable=x)', HIGH),
        ("subprocess.run(x, shell=extra)", HIGH_TO_REVIEW),
        # 4: a free element is an option the attacker chooses.
        ('subprocess.run(["ls", x])', MEDIUM),
        ('subprocess.run(["git", "status", x])', MEDIUM),
        ('subprocess.run(["git", "push", "origin", x])', HIGH),
        ('subprocess.run(["/usr/bin/git", "push", "origin", x])', HIGH),
        # 5, 5b, 5c: a constant prefix.
        ('subprocess.run(["git", "tag", f"v{x}"])', None),
        ('subprocess.run(["git", "commit", "-m", f"release {x}"])', None),
        ('subprocess.run(["curl", f"--output={x}"])', MEDIUM),
        ('subprocess.run(["git", "fetch", f"--upload-pack={x}"])', HIGH),
        ('subprocess.run(["ssh", f"-o{x}", "host"])', HIGH),
        ('subprocess.run(["ls", f"--{x}"])', MEDIUM),
        # 6: after the end of options, for a program known to honour it.
        ('subprocess.run(["git", "log", "--", x])', None),
        ('subprocess.run(["ls", "--", x])', MEDIUM),
        # 7: after an option that may take a value.
        ('subprocess.run(["ssh", "-o", x, "host"])', HIGH),
        ('subprocess.run(["sh", "-c", x])', HIGH),
        ('subprocess.run(["find", ".", "-exec", x, ";"])', HIGH),
        ('subprocess.run(["xcrun", "notarytool", "--keychain", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["git", "push", "--force", x])', HIGH_TO_REVIEW),
        # Short options grouped in one element, read as getopt does.
        ('subprocess.run(["rm", "-rf", x])', MEDIUM),
        ('subprocess.run(["rm", "-r", "-f", x])', MEDIUM),
        ('subprocess.run(["rm", "-rz", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["ssh", "-vo", x, "host"])', HIGH),
        ('subprocess.run(["ssh", "-ov", x, "host"])', HIGH),
        # An established option judges the value it takes, whatever its prefix.
        ('subprocess.run(["sh", "-c", f"echo {x}"])', HIGH),
        ('subprocess.run(["bash", "-c", "ls " + x])', HIGH),
        ('subprocess.run(["ssh", "-o", f"ProxyCommand={x}", "host"])', HIGH),
        ('subprocess.run(["git", "-c", f"core.sshCommand={x}", "fetch"])', HIGH),
        ('subprocess.run(["find", ".", "-exec", f"sh -c {x}", ";"])', HIGH),
        ('subprocess.run(["python3", "-c", f"print({x})"])', HIGH),
        ('subprocess.run([sys.executable, "-c", f"print({x})"])', HIGH),
        ('subprocess.run(["python3.12", "-c", x])', HIGH),
        ('subprocess.run(["cmd", "/c", f"dir {x}"])', HIGH),
        ('subprocess.run(["cmd", "/c", "dir", x])', HIGH),
        ('subprocess.run(["powershell", "-Command", x])', HIGH),
        ('subprocess.run(["git", "commit", "-m", x])', None),
        ('subprocess.run(["gh", "release", "create", "v1", "--title", f"release {x}"])', None),
        ('subprocess.run(["gh", "workflow", "run", "main.yml", "--ref", x])', None),
        ('subprocess.run(["notmodelled", "-c", f"echo {x}"])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["bash", "-lc", x])', HIGH),
        ('subprocess.run(["sh", "-ec", f"echo {x}"])', HIGH),
        ('subprocess.run(["tar", f"-I{x}", "-xf", "a.tar"])', HIGH),
        ('subprocess.run(["safe", "-c", x], executable="/bin/sh")', HIGH),
        # Operands that are a command: a remote shell, a wrapper, a batch file.
        ('subprocess.run(["ssh", "user@host", "--", x])', HIGH),
        ('subprocess.run(["ssh", "host", f"cat {x}"])', HIGH),
        ('subprocess.run(["sudo", x])', HIGH),
        ('subprocess.run(["env", x])', HIGH),
        ('subprocess.run(["timeout", "5", x])', HIGH),
        ('subprocess.run(["build.bat", x])', HIGH),
        ('subprocess.run(["git.exe", "push", "origin", x])', HIGH),
        (r'subprocess.run(["C:\\Git\\bin\\git.exe", "push", "origin", x])', HIGH),
        # An operand after the end of options, anywhere before it.
        ('subprocess.run(["git", "log", "--", "a", x])', None),
        ('subprocess.run(["rm", "-rf", "--", x])', None),
        # Where shell comes from, and lists the module cannot read.
        ('subprocess.Popen(["ls", x], -1, None, None, None, None, None, True, True)', HIGH),
        ('subprocess.run(["ls", x], **extra)', HIGH_TO_REVIEW),
        ('subprocess.Popen(args=["ls", x])', MEDIUM),
        ('subprocess.run(("ls", x))', MEDIUM),
        ('cmd = ["ls", x]\n    subprocess.run(cmd)', MEDIUM),
        ('cmd = ["ls"]\n    cmd.append(x)\n    subprocess.run(cmd)', HIGH),
        ('cmd = ["ls", "-l"]\n    cmd.insert(0, x)\n    subprocess.run(cmd)', HIGH),
        ('cmd = ["ls"]\n    cmd += [x]\n    subprocess.run(cmd)', HIGH),
        ('cmd = ["ls", "-l"]\n    cmd[0] = x\n    subprocess.run(cmd)', HIGH),
        # Second review: an element of unknown value before the input leaves it to review.
        ('subprocess.run(["tool", extra, f"echo {x}"])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["sh", extra, f"echo {x}"])', HIGH),
        # A shell's -c is a flag: its first operand is the command, later ones are $1, $2...
        ('subprocess.run(["sh", "-ce", f"echo {x}"])', HIGH),
        ('subprocess.run(["bash", "-c", "-e", f"echo {x}"])', HIGH),
        ('subprocess.run(["sh", "-c", "--", f"echo {x}"])', HIGH),
        ('subprocess.run(["sh", "-lc", x])', HIGH),
        ('subprocess.run(["bash", "-o", "pipefail", "-c", x])', HIGH),
        ('subprocess.run(["sh", "-c", "echo $1", "sh", f"v{x}"])', None),
        # After the first word of a remote command, ssh operands are shell text.
        ('subprocess.run(["ssh", "host", "ls", f"-l{x}"])', HIGH),
        ('subprocess.run(["ssh", "host", "ls", f"--color={x}"])', HIGH),
        # A command inside the command: find -exec, a wrapper's program.
        ('subprocess.run(["find", ".", "-exec", "sh", "-c", x, ";"])', HIGH),
        ('subprocess.run(["find", ".", "-exec", "rm", x, ";"])', MEDIUM),
        ('subprocess.run(["sudo", "ls", x])', MEDIUM),
        ('subprocess.run(["sudo", "sh", "-c", f"echo {x}"])', HIGH),
        # Inert values only where the subcommand is established, and one element only.
        ('subprocess.run(["git", "commit", "-m", *x.split()])', MEDIUM),
        ('subprocess.run(["git", "-C", "repo", "branch", "-m", x])', HIGH_TO_REVIEW),
        ('subprocess.run(["gh", "--title", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["git", "clone", f"-u{x}", "url"])', HIGH),
        ('subprocess.run(["git", "clone", "-u", x, "url"])', HIGH),
        # Windows: PowerShell runs its operands, parameters ignore case, /c may be glued.
        ('subprocess.run(["powershell", f"Get-Item {x}"])', HIGH),
        ('subprocess.run(["powershell", "-NoProfile", f"Get-Item {x}"])', HIGH),
        ('subprocess.run(["powershell", "-COMMAND", x])', HIGH),
        ('subprocess.run(["cmd", f"/c{x}"])', HIGH),
        ('subprocess.run(["CMD.EXE", "/C", x])', HIGH),
        # An executable that cannot be read leaves the program unknown.
        ('subprocess.run(["git", "commit", "-m", x], executable=extra)', MEDIUM_TO_REVIEW),
        ('subprocess.run(["x", "-c", f"echo {x}"], executable=sys.executable)', HIGH),
        # Third review: options a shell reads, assignments before a wrapper's program.
        ('subprocess.run(["bash", "-O", "extglob", "-c", f"echo {x}"])', HIGH),
        ('subprocess.run(["bash", "--rcfile", "f", "-c", f"echo {x}"])', HIGH),
        ('subprocess.run(["sh", "+e", "-c", f"echo {x}"])', HIGH),
        ('subprocess.run(["bash", "+o", "history", "-c", f"echo {x}"])', HIGH),
        ('subprocess.run(["env", "PATH=/usr/bin", x])', HIGH),
        ('subprocess.run(["sudo", "A=1", x])', HIGH),
        ('subprocess.run(["env", "A=1", "sh", "-c", f"echo {x}"])', HIGH),
        ('subprocess.run(["env", "A=1", "ls", x])', MEDIUM),
        # An unknown program may run its operands: kept for review, never refuted.
        ('subprocess.run([extra, f"echo {x}"])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["ls", f"echo {x}"], -1, extra)', MEDIUM_TO_REVIEW),
        ('subprocess.run([shutil.which("ssh"), "host", f"cat {x}"])', HIGH),
        ('subprocess.run([shutil.which("bash"), "-c", f"echo {x}"])', HIGH),
        # An interpreter runs the script its first operand names, unless code is given:
        # execution is possible, exploitability depends on the file, so high to review. An
        # input that starts the element may as well be a code option (-e<code>#.pl): high.
        ('subprocess.run(["bash", f"/tmp/{x}.sh"])', HIGH_TO_REVIEW),
        ('subprocess.run(["sh", x])', HIGH_TO_REVIEW),
        ('subprocess.run(["bash", "-x", "--", f"run-{x}.sh"])', HIGH_TO_REVIEW),
        ('subprocess.run(["python3", f"scripts/{x}.py"])', HIGH_TO_REVIEW),
        ('subprocess.run([sys.executable, f"tools/{x}.py", "--flag"])', HIGH_TO_REVIEW),
        ('subprocess.run(["python3", "-m", f"pkg.{x}"])', HIGH_TO_REVIEW),
        ('subprocess.run(["perl", f"lib/{x}.pl"])', HIGH_TO_REVIEW),
        ('subprocess.run(["perl", f"{x}.pl"])', HIGH),
        ('subprocess.run(["node", f"app/{x}.js"])', HIGH_TO_REVIEW),
        ('subprocess.run(["node", f"{x}.js"])', HIGH),
        # Code given by an option runs; the operands after it are the script's arguments.
        ('subprocess.run(["perl", "-e", f"print {x}"])', HIGH),
        ('subprocess.run(["ruby", "-e", x])', HIGH),
        ('subprocess.run(["node", "--eval", x])', HIGH),
        ('subprocess.run(["php", "-r", x])', HIGH),
        ('subprocess.run(["python3", "-c", "import sys; print(sys.argv[1])", f"v{x}"])', None),
        ('subprocess.run(["bash", "script.sh", f"v{x}"])', None),
        ('subprocess.run(["python3", "script.py", f"--name={x}"])', MEDIUM),
        # Fourth review: options that choose code, arguments of a script, interpreter names.
        ('subprocess.run(["python", "-W", x, "s.py"])', HIGH_TO_REVIEW),
        ('subprocess.run(["python", f"-W{x}"])', HIGH_TO_REVIEW),
        ('subprocess.run(["python", x])', HIGH),
        ('subprocess.run(["node", x])', HIGH),
        ('subprocess.run(["node", "app.js", x])', MEDIUM),
        ('subprocess.run(["node", "app.js", "-e", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["perl", "x.pl", "-e", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["python3", "script.py", x])', MEDIUM),
        ('subprocess.run(["python", "-m", "pkg", x])', MEDIUM),
        ('subprocess.run(["node", "--eval=code", f"v{x}"])', None),
        ('subprocess.run(["nodejs", f"s/{x}"])', HIGH_TO_REVIEW),
        ('subprocess.run(["pypy3", f"tools/{x}.py"])', HIGH_TO_REVIEW),
        ('subprocess.run(["perl5.36", f"lib/{x}.pl"])', HIGH_TO_REVIEW),
        ('subprocess.run(["perl", f"-M{x}", "s.pl"])', HIGH),
        ('subprocess.run(["ruby", "-r", x, "s.rb"])', HIGH_TO_REVIEW),
        ('subprocess.run(["php", "-R", f"echo {x};"])', HIGH),
        ('subprocess.run(["bash", "-s", f"v{x}"])', None),
        ('subprocess.run(["bash", "-s", x])', MEDIUM),
        # Fifth review: perl, ruby, node and php read options after the code, until an
        # operand; python and the shells do not. A shell's lone - ends its options.
        ('subprocess.run(["perl", "-e", "CODE", "-e", f"c{x}"])', HIGH),
        ('subprocess.run(["perl", "-e", "CODE", x])', HIGH),
        ('subprocess.run(["ruby", "-e", "CODE", x])', HIGH),
        ('subprocess.run(["node", "-e", "CODE", f"--eval={x}"])', HIGH),
        ('subprocess.run(["perl", "-e", "CODE", f"v{x}"])', None),
        ('subprocess.run(["perl", "-e", "CODE", "arg", f"v{x}"])', None),
        ('subprocess.run(["python", "-c", "CODE", "-c", x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["bash", "-", f"s/{x}.sh"])', HIGH_TO_REVIEW),
        ('subprocess.run(["sh", "-", x])', HIGH_TO_REVIEW),
        ('subprocess.run(["perl", "-w", "s.pl", f"v{x}"])', None),
        ('subprocess.run(["perl", "-I", "lib", "s.pl", f"v{x}"])', None),
        ('subprocess.run(["ruby", "-w", "s.rb", f"v{x}"])', None),
        ('subprocess.run(["node", "--inspect", "app.js", f"v{x}"])', None),
        ('subprocess.run(["php", "-f", "s.php", f"v{x}"])', None),
        ('subprocess.run(["php", "-f", f"s/{x}.php"])', HIGH_TO_REVIEW),
        ('subprocess.run(["pwsh", f"s/{x}.ps1"])', HIGH_TO_REVIEW),
        ('subprocess.run(["pwsh", "-File", f"s/{x}.ps1"])', HIGH_TO_REVIEW),
        ('subprocess.run(["powershell", "-File", "s.ps1", f"v{x}"])', None),
        ('subprocess.run(["pyw", f"s/{x}.py"])', HIGH_TO_REVIEW),
        ('subprocess.run(["python3-dbg", f"s/{x}.py"])', HIGH_TO_REVIEW),
        # Sixth review: every element after pwsh -Command is the command; node -pe.
        ('subprocess.run(["pwsh", "-Command", "Get-Item", f"v{x}"])', HIGH),
        ('subprocess.run(["pwsh", "-NoProfile", "-Command", "Get-Item", f"v{x}"])', HIGH),
        ('subprocess.run(["pwsh", "-ec", "AAA", f"v{x}"])', HIGH),
        ('subprocess.run(["pwsh", "-c", "echo", x])', HIGH),
        ('subprocess.run(["sudo", "pwsh", "-c", "Get-Item", x])', HIGH),
        ('subprocess.run(["node", "-pe", f"console.log({x})"])', HIGH),
        ('subprocess.run(["node", "-pe", "CODE", x])', HIGH),
        # Unpacked parts keep their place in the command.
        ('subprocess.run(["xcrun", "notarytool", *(["--keychain", x])])', MEDIUM_TO_REVIEW),
        ("subprocess.run([*extra, x])", HIGH),
        ('subprocess.run(["ls", *extra, x])', MEDIUM_TO_REVIEW),
        ('subprocess.run(["ls", *x.split()])', MEDIUM),
    ],
)
def test_the_result_follows_what_the_attacker_controls(
    call: str, expected: tuple[str, str, str] | None
) -> None:
    assert judged(call) == ([] if expected is None else [expected])


def test_an_unpacked_element_keeps_its_place_in_a_list_or_tuple_display() -> None:
    module = lower_module(
        build_hir(
            SourceManager().add_source("m.py", "def f(a, b):\n    use([1, *a, 2, *b], (*a, 1))\n")
        )
    )
    instructions = [i for block in module.functions[0].blocks for i in block.instructions]
    (built_list,) = [i for i in instructions if isinstance(i, BuildList)]
    (built_tuple,) = [i for i in instructions if isinstance(i, BuildTuple)]

    assert built_list.unpacked_at == (1, 3)
    assert built_tuple.unpacked_at == (0,)


def test_a_deeply_nested_command_is_still_read() -> None:
    wrappers = '"sudo", ' * 500
    assert judged(f"subprocess.run([{wrappers}x])") == [HIGH]
