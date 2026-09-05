"""Security models for the Python standard library (architecture §16)."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Model, Sanitizer, Sink, Source, TaintKind, Validator

_ENVIRONMENT_KINDS = TaintKind.ALL & ~(TaintKind.COMMAND | TaintKind.PATH)
_PROCESS_OUTPUT_KINDS = TaintKind.ALL & ~TaintKind.PATH


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class PythonStdlibModels(ModelPlugin):
    name: ClassVar[str] = "python-stdlib-models"
    models: ClassVar[tuple[Model, ...]] = (
        Source(_sym("builtins.input"), "stdin"),
        Source(_sym("sys.stdin"), "stdin"),
        # Operator-controlled inputs. A command-line tool is expected to open the paths
        # it is given; the environment is set by whoever runs the program, so a command
        # or a path built from it is not an injection; the output of a local process is
        # not a path either, but a downloaded script piped into a shell is a real flaw.
        Source(_sym("sys.argv"), "argv", TaintKind.ALL & ~TaintKind.PATH),
        Source(_sym("os.environ"), "environment", _ENVIRONMENT_KINDS),
        Source(_sym("subprocess.run.stdout"), "process-output", _PROCESS_OUTPUT_KINDS),
        Source(_sym("subprocess.check_output"), "process-output", _PROCESS_OUTPUT_KINDS),
        Source(_sym("subprocess.getoutput"), "process-output", _PROCESS_OUTPUT_KINDS),
        Source(_sym("subprocess.Popen.communicate"), "process-output", _PROCESS_OUTPUT_KINDS),
        Sink(_sym("os.system"), TaintKind.COMMAND),
        Sink(_sym("os.popen"), TaintKind.COMMAND),
        Sink(_sym("subprocess.run"), TaintKind.COMMAND),
        Sink(_sym("subprocess.call"), TaintKind.COMMAND),
        Sink(_sym("subprocess.check_call"), TaintKind.COMMAND),
        Sink(_sym("subprocess.check_output"), TaintKind.COMMAND),
        Sink(_sym("subprocess.Popen"), TaintKind.COMMAND),
        Sink(_sym("builtins.eval"), TaintKind.CODE),
        Sink(_sym("builtins.exec"), TaintKind.CODE),
        Sink(_sym("builtins.open"), TaintKind.PATH),
        Sink(_sym("os.remove"), TaintKind.PATH),
        Sink(_sym("os.unlink"), TaintKind.PATH),
        Sink(_sym("os.rmdir"), TaintKind.PATH),
        Sink(_sym("shutil.rmtree"), TaintKind.PATH),
        Sink(_sym("urllib.request.urlopen"), TaintKind.SSRF),
        *(
            Sink(
                _sym(f"sqlite3.connect{cursor}.{method}"),
                TaintKind.SQL | TaintKind.CREDENTIAL,
                ((TaintKind.SQL, (0,)),),
            )
            for cursor in ("", ".cursor")
            for method in ("execute", "executemany", "executescript")
        ),
        Sanitizer(_sym("shlex.quote"), TaintKind.COMMAND),
        Sanitizer(_sym("html.escape"), TaintKind.HTML),
        Sink(_sym("pickle.loads"), TaintKind.DESERIALIZATION),
        Sink(_sym("pickle.load"), TaintKind.DESERIALIZATION),
        Sink(_sym("pickle.Unpickler"), TaintKind.DESERIALIZATION),
        Sink(_sym("marshal.loads"), TaintKind.DESERIALIZATION),
        Sink(_sym("marshal.load"), TaintKind.DESERIALIZATION),
        Sink(_sym("shelve.open"), TaintKind.DESERIALIZATION),
        Sink(_sym("dill.loads"), TaintKind.DESERIALIZATION),
        Sink(_sym("jsonpickle.decode"), TaintKind.DESERIALIZATION),
        Sink(_sym("yaml.load"), TaintKind.DESERIALIZATION),
        Sink(_sym("yaml.unsafe_load"), TaintKind.DESERIALIZATION),
        Sink(_sym("yaml.full_load"), TaintKind.DESERIALIZATION),
        Sanitizer(_sym("os.path.basename"), TaintKind.PATH),
        Validator(_sym("re.fullmatch"), argument=1),
        Validator(_sym("re.compile.fullmatch")),
    )
