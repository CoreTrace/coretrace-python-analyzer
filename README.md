# CoreTrace Python Analyzer

A standalone, Python-specific static analysis frontend for CoreTrace.

The analyzer loads source through a source manager, adapts parsed Python into a
parser-independent high-level representation (PyHIR), and lowers a deliberately small
language subset to deterministic PyIR. CFG construction, SSA, data-flow, and security rules
are intentionally deferred.

```text
Python source -> SourceManager -> frontend -> PyHIR -> semantic imports and scopes -> PyIR
```

The long-term engine architecture and incremental migration plan are recorded in
[`docs/architecture.md`](docs/architecture.md).

## Development

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m mypy
python -m pytest
python -m ruff check .
```

## Check a file with plugins

```bash
coretrace-python-analyzer --check app.py --plugins plugins/
coretrace-python-analyzer --check src/ --plugins plugins/ --format sarif > report.sarif
```

Given a directory, every Python file below it is analysed as one project: modules are
named after their packages, and taint follows calls into functions defined in other files
through a project-wide index of function summaries iterated to a fixpoint. Hidden and
tooling directories (`.venv`, `node_modules`, `__pycache__`, `build`, `dist`) are skipped.
The dependency files at the root (`requirements*.txt`, `pyproject.toml`, `poetry.lock`,
`uv.lock`) are resolved into a dependency graph. Plugins may contribute advisories; the
shipped `dependency/` plugins report a requirement that allows a vulnerable version at
its line, and every call in the project to an API the advisory affects. When
attacker-controlled data reaches such a call, the engine correlates the four facts into
one critical `exploitable-vulnerability` finding, judged like any other flow. The shipped
advisory database is a small offline sample; a live OSV feed is future work.

`--cache DIR` keeps the results of a directory check on disk, one JSON entry per module.
The entry is keyed by the module's source, the engine and plugin versions, the plugin
code, the security models, the advisories, the dependency graph and the keys of the
modules it imports transitively. On the next run a module whose key is unchanged is
served from the cache: its function summaries seed the project index, its call sites
serve the project plugins and its findings are reported as they were, so editing one file
re-analyses that file and the modules that import it only. Entries are plain data, never
code; an unreadable entry is simply recomputed.

Modules are analysed by strongly connected components of the module graph, imports
first, so a module starts with the final summaries of everything it imports and mutually
importing modules are iterated together. `--jobs N` analyses the components of one wave
in `N` processes; each worker rebuilds the configuration from the project root and the
plugin roots and hands back summaries, call sites and findings as plain data, so the
result is the same whatever `N`. Once a module's results are extracted, its intermediate
representation and derived results are dropped and only its semantic tables stay in
memory.

`--plugins` is a directory searched recursively for `plugin.toml` manifests and may be
repeated. The repository ships a first set under `plugins/`: security models for the
standard library, Flask, FastAPI, Django, SQLAlchemy and the Requests and httpx clients (`models/`), taint detectors for SQL
injection, command injection, path traversal, SSRF and XSS (`security/`), and syntactic
detectors for `eval`/`exec` and weak hashes (`syntax/`). Route handlers of Flask and
FastAPI receive their parameters as HTTP input; `request.args` and its siblings are HTTP
sources. Django views are undecorated, so a parameter annotated with a request class
(`request: HttpRequest`), a method of a class-based view and a view decorated by one of
Django's or Django REST framework's view decorators receive HTTP input; a bare
`request` parameter without any of these is not recognised, and URL configurations are
not read. Requests and httpx calls are SSRF sinks whose responses are untrusted
`http-response` sources. Model plugins contribute sources, sinks and sanitizers;
detectors consume the shared taint result, so adding a framework model makes every
detector aware of it. Taint follows calls between functions of the same module through
function summaries: a tainted argument passed to a helper that reaches a sink is reported
at the call site, and a helper returning attacker-controlled data taints its result.
Each flow is then judged: a dominating guard that proves the value safe (`isdigit()`,
membership in a constant allowlist, equality with a constant) refutes it and it is not
reported; a guard that only mentions the value makes it a hotspot with medium confidence;
the verdict and its evidence are in the finding metadata. `--format` is `text` (default), `json` or `sarif`. Exit status is 0 when nothing
was found, 1 when findings were reported, and 2 on a usage or analysis error.

## Emit PyIR

```bash
coretrace-python-analyzer --emit-ir example.py
# or, without installing:
PYTHONPATH=src python -m coretrace_python --emit-ir example.py
```

Currently supported inside functions: parameters with defaults and keyword-only or star
forms, decorators, assignments to names, attributes, items and unpacked tuples, augmented
assignment, list, tuple and dict literals, `and`/`or`, chained comparisons, keyword
arguments, `with`, `assert`, `try`/`except`/`else`/`finally`, `await`, `yield`,
`if`/`elif`/`else`, `while`, `for`, `break`, `continue` and `raise`. Blocks inside a `try`
body carry exception edges to the handlers; `finally` is modelled on the normal path only. Methods of module-level classes are analysed like functions; other module-level
code is skipped. A function using syntax outside this subset is reported by `--check` as
an `unsupported-syntax` note and the other functions are still analysed. Each function is
emitted as its control-flow graph: one block per basic block, ending in an explicit
terminator (`branch`, `jump`, `return`, `raise`, `for_next`). Add `--ssa` to print the
static single assignment form: locals become numbered values, merges get `phi`
instructions and unassigned paths read an explicit `undefined` value.
Unsupported syntax produces a source-located diagnostic and a non-zero exit status.

Names are resolved to canonical symbols through lexical scopes, imports and builtins.
Calling a symbol denotes that symbol, so `app = Flask(__name__)` makes `app.route` resolve
to `python.flask.Flask.route` and `sqlite3.connect(p).cursor().execute` resolves to
`python.sqlite3.connect.cursor.execute`; model plugins register those chains.
Import aliases do not change an API's identity, so all of the following resolve to
`python.os.system`:

```python
import os
from os import system
from os import system as run
```

Relative imports resolve against the module's dotted name, derived from the enclosing
`__init__.py` packages. Builtins resolve to `python.builtins.<name>`. Names introduced by
wildcard imports stay unresolved and are emitted as `global`.
