"""Security models for the Python standard library (architecture §16)."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Model, Sanitizer, Sink, Source, TaintKind, Validator


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class PythonStdlibModels(ModelPlugin):
    name: ClassVar[str] = "python-stdlib-models"
    models: ClassVar[tuple[Model, ...]] = (
        Source(_sym("builtins.input"), "stdin"),
        Source(_sym("sys.stdin"), "stdin"),
        Source(_sym("sys.argv"), "argv"),
        Source(_sym("os.environ"), "environment"),
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
            Sink(_sym(f"sqlite3.connect{cursor}.{method}"), TaintKind.SQL)
            for cursor in ("", ".cursor")
            for method in ("execute", "executemany", "executescript")
        ),
        Sanitizer(_sym("shlex.quote"), TaintKind.COMMAND),
        Sanitizer(_sym("html.escape"), TaintKind.HTML),
        Sanitizer(_sym("os.path.basename"), TaintKind.PATH),
        Validator(_sym("re.fullmatch"), argument=1),
        Validator(_sym("re.compile.fullmatch")),
    )
