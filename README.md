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
tooling directories (`.venv`, `node_modules`, `__pycache__`, `build`, `dist`) are skipped,
and so is any virtual environment, recognised by its `pyvenv.cfg` whatever its name. A
module or package whose name is not an identifier is analysed like any other.
The dependency files at the root (`requirements*.txt`, `pyproject.toml`, `poetry.lock`,
`uv.lock`) are resolved into a dependency graph. Plugins may contribute advisories; the
shipped `dependency/` plugins report a requirement that allows a vulnerable version at
its line, and every call in the project to an API the advisory affects. When
attacker-controlled data reaches such a call, the engine correlates the four facts into
one critical `exploitable-vulnerability` finding, judged like any other flow. The shipped
advisory database is a small offline sample. A real feed stays offline too:
`--import-advisories SRC OUT` converts a public OSV dump (a JSON file, a directory of
them or a zip archive) into a local advisory file once, and a directory check reads
`advisories.json` at the project root plus the files passed with `--advisories`, the
local file winning over a plugin for the same advisory. OSV records name no affected
APIs, so imported advisories feed the requirement checks and the SBOM; add
`affected_symbols` by hand to a local entry and it feeds reachability and correlation
too. A `coretrace-policy.toml` at the root, or the file passed with `--policy`, denies
packages (`denied-dependency`), requires pins (`unpinned-dependency`) and lists accepted
advisories whose findings are dropped:

```toml
[dependencies]
deny = ["pycrypto"]
require_pinned = true

[advisories]
ignore = ["CVE-2020-1747"]
```

`--sbom PATH` writes a CycloneDX 1.5 bill of materials of the dependency graph, one
component per requirement with its package URL, and the advisories affecting them as
vulnerabilities. The shipped `secrets/` plugin scans every string literal of the Python
sources for provider-specific secret formats (AWS, GitHub, Slack, Stripe, Google, private
keys, JWTs, SendGrid, Twilio), for credential-like names bound to a real value
(`password`, `token`, `api_key` and the like, bound by name, attribute or constant key
such as `app.config['SECRET_KEY']`, placeholders excluded) and for opaque
high-entropy tokens; one finding per literal, at high, medium and low confidence
respectively, with a redacted preview and never the secret itself. The `config-secrets`
plugin applies the same rules to the key-value pairs of `.env`, YAML, TOML, JSON, INI and
properties files under the project root. Other plugins add providers by subclassing
`SecretDetector` with their own patterns.

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
injection, command injection, path traversal, SSRF, XSS and plaintext credential storage
(`security/`), and syntactic
detectors for `eval`/`exec`, weak hashes, `app.run(debug=True)` and HTTP client calls
without a timeout (`syntax/`). Route handlers of Flask and
FastAPI receive their parameters as HTTP input, whether the application is created
directly (`app = Flask(__name__)`) or by a project factory whose summary returns it
(`app = create_app()`); `request.args` and its siblings are HTTP
sources. A parameter named `password` or the like is a credential wherever it appears: stored
in a database without passing through a hashing function it is a
`plaintext-credential-storage` finding at medium confidence, since a name is a hint.
Django views are undecorated, so a parameter annotated with a request class
(`request: HttpRequest`), a method of a class-based view and a view decorated by one of
Django's or Django REST framework's view decorators receive HTTP input; a bare
`request` parameter without any of these is not recognised, and URL configurations are
not read. Requests and httpx calls are SSRF sinks whose responses are untrusted
`http-response` sources. Model plugins contribute sources, sinks and sanitizers;
detectors consume the shared taint result, so adding a framework model makes every
detector aware of it. Taint follows calls between functions of the same module through
function summaries: a tainted argument passed to a helper that reaches a sink is reported
at the call site, and a helper returning attacker-controlled data taints its result.
Taint also follows objects, not only values: a coarse heap abstraction gives every
allocation site one abstract object with an `elements` and an `attributes` location, so
`b = a; b.append(user_input); sink(a[0])`, dictionary and attribute stores, `extend`,
`insert`, `add`, `update` and iteration all carry taint through the container. Function
summaries record the parameters a function mutates and the module globals it touches, so
a helper that fills a list taints the caller's list, across files too.
Each flow is then judged: a dominating guard that proves the value safe (`isdigit()`,
membership in a constant allowlist, equality with a constant) refutes it and it is not
reported; a guard that only mentions the value makes it a hotspot with medium confidence;
the verdict and its evidence are in the finding metadata. Every check ends with a
coverage line, `coverage: 3/4 files, 5/6 functions`, and the JSON report carries the
per-file detail, so "no findings" can be told from "nothing analysed". Three more kinds of evidence
apply: a value proven numeric by the range analysis (`int()`, `len()`, arithmetic,
bounded by the comparisons on the path) cannot inject; a `Validator` model names a
callable whose truth proves one of its arguments, such as `re.fullmatch`; and an
`AuthorizationGuard` model names a decorator or a condition that restricts who reaches
the code, such as `login_required`, behind which a flow is a hotspot rather than a
vulnerability. Plugins contribute validators and authorization guards through their
models, like sources and sinks. `--format` is `text` (default), `json` or `sarif`. Exit status is 0 when nothing
was found, 1 when findings were reported, and 2 on a usage or analysis error.

## Emit PyIR

```bash
coretrace-python-analyzer --emit-ir example.py
# or, without installing:
PYTHONPATH=src python -m coretrace_python --emit-ir example.py
```

Currently supported inside functions: parameters with defaults and keyword-only or star
forms, decorators, assignments to names, attributes, items and unpacked tuples, augmented
assignment, list, tuple and dict literals with `*` and `**` unpacking, f-strings, slices,
`and`/`or`, chained comparisons, keyword and starred arguments, `with`, `assert`,
`try`/`except`/`else`/`finally`, `await`, `yield`, `if`/`elif`/`else`, `while`, `for`
with name or tuple targets, `break`, `continue` and `raise`, `from` clause included,
conditional expressions and comprehensions, laid out as real branches and loops over a
synthetic local, set literals, chained assignments, assignments to `global` names, and
lambdas and nested function definitions as function values whose bodies are not analysed
yet, `del`, loop `else` clauses, and `match` over literal, singleton, capture, wildcard
and or-patterns with guards, laid out as an `if` chain. Not yet: sequence, mapping and
class patterns, `nonlocal` assignments, classes defined inside functions, and a
conditional expression or comprehension inside a `while` condition. Blocks inside a `try`
body carry exception edges to the handlers; `finally` is modelled on the normal path only. Methods of module-level classes are analysed like functions; other module-level
code is skipped. An import inside a function is shown where it runs, as an `import`
instruction naming the module, the bound name and the canonical symbol. A function using syntax outside this subset is reported by `--check` as
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
