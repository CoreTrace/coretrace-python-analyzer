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
coretrace-python-analyzer --check app.py --plugins plugins/ --format sarif > report.sarif
```

`--plugins` is a directory searched recursively for `plugin.toml` manifests and may be
repeated. The repository ships a first set under `plugins/`: security models for the
standard library, Flask, FastAPI and SQLAlchemy (`models/`), taint detectors for SQL
injection, command injection, path traversal, SSRF and XSS (`security/`), and syntactic
detectors for `eval`/`exec` and weak hashes (`syntax/`). Route handlers of Flask and
FastAPI receive their parameters as HTTP input; `request.args` and its siblings are HTTP
sources. Model plugins contribute sources, sinks and sanitizers;
detectors consume the shared taint result, so adding a framework model makes every
detector aware of it. Taint follows calls between functions of the same module through
function summaries: a tainted argument passed to a helper that reaches a sink is reported
at the call site, and a helper returning attacker-controlled data taints its result. `--format` is `text` (default), `json` or `sarif`. Exit status is 0 when nothing
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
arguments, `with`, `assert`, `if`/`elif`/`else`, `while`, `for`, `break`, `continue` and
`raise`. Methods of module-level classes are analysed like functions; other module-level
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
