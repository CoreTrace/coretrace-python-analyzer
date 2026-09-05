# Using CoreTrace Python Analyzer

CoreTrace Python Analyzer finds security vulnerabilities in Python code: injection flaws
by following attacker-controlled data through the program, dangerous API usage, secrets
committed in sources and configuration, and vulnerable or forbidden dependencies. It runs
on a single file or a whole project, offline, with no runtime dependency.

## Install

```bash
pip install coretrace-python-analyzer
```

Python 3.11 or later. The command `coretrace-python-analyzer` is installed with the
package; `python -m coretrace_python` is equivalent.

## Quick start

```bash
coretrace-python-analyzer --check src/
```

Every Python file under `src/` is analysed as one project and the findings are printed
one per line, followed by a count and a coverage line:

```text
src/app.py:44:26: high command-injection: Command injection: http input reaches python.os.system through services.run_command [command_injection]
src/app.py:71:14: high dangerous-eval: call to python.builtins.eval executes dynamically built code [code_injection]
2 findings
coverage: 2/2 files, 12/12 functions
```

The exit status is 0 when nothing was found, 1 when findings were reported and 2 on a
usage or analysis error, so the command can gate a pipeline as it is.

## Command line

```text
coretrace-python-analyzer [--check | --emit-ir [--ssa]] [options] [path]
```

| Option | Effect |
|---|---|
| `--check` | Run the loaded plugins on `path` and report their findings. |
| `path` | A Python file, or a directory analysed as a project. |
| `--format {text,json,sarif}` | Report format, `text` by default. |
| `--plugins DIR` | Load the plugins found under `DIR` on top of the bundled ones. Repeatable. |
| `--no-bundled-plugins` | Do not load the plugins shipped with the package. |
| `--cache DIR` | Keep per-module results under `DIR` and reuse them for unchanged modules. |
| `--jobs N` | Analyse independent modules in `N` processes. |
| `--sbom PATH` | Write a CycloneDX bill of materials of the dependencies to `PATH`. |
| `--advisories FILE` | Read a local advisory file in addition to `advisories.json` at the root. Repeatable. |
| `--policy FILE` | Apply this dependency policy instead of `coretrace-policy.toml` at the root. |
| `--import-advisories SRC OUT` | Convert an OSV dump into the local advisory file `OUT`, then exit. |
| `--emit-ir` | Print the intermediate representation of `path` instead of checking it. |
| `--ssa` | With `--emit-ir`, print the static single assignment form. |
| `--help` | Show the options and exit. |

`--cache`, `--jobs`, `--sbom`, `--advisories` and `--policy` apply to a directory check.

## What is analysed

Given a directory, every `.py` file below it is a module of one project, named after
its package (`app/views.py` is `app.views`). Hidden directories, `node_modules`,
`__pycache__`, `build`, `dist` and any virtual environment, recognised by its
`pyvenv.cfg` whatever its name, are skipped. Dependency files at the root
(`requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`) are read into a
dependency graph. Configuration files under the root (`.env`, YAML, TOML, JSON, INI,
properties) are scanned for secrets.

Functions and methods are analysed; module-level statements outside functions are not.
A function using syntax outside the supported subset is reported as an
`unsupported-syntax` note and the other functions are still analysed; a file Python
itself cannot parse is reported as a `syntax-error`. The coverage line and the JSON
report's per-file detail tell "no findings" from "nothing analysed".

Taint follows values between functions and across files through function summaries,
into objects (containers, attributes, instances of the project's own classes) and through
closures. Flask, FastAPI and Django route handlers, class-based views and registered
URL patterns receive HTTP input; click and Typer commands receive `argv` input; `input()`,
`sys.argv`, environment variables and the responses of HTTP clients are further sources.

## Rules

Findings carry a rule id, a severity (`critical`, `high`, `medium`, `low`) and a
confidence (`high`, `medium`, `low`).

### Taint flows

Reported when attacker-controlled data reaches a sensitive call without passing through
a sanitizer for that kind of sink.

| Rule | Reached sink |
|---|---|
| `command-injection` | Shell or process execution (`os.system`, `subprocess` with a string, …). |
| `sql-injection` | A database statement (`cursor.execute`, SQLAlchemy `text`, Django `raw`, …). Parameters of a parameterised query are not statements. |
| `path-traversal` | A file system path (`open`, `send_file`, `os.remove`, …). |
| `ssrf` | The URL of an HTTP client request (Requests, httpx, `urllib`). |
| `xss` | An HTTP response body built without escaping. |
| `insecure-deserialization` | `pickle`, `yaml.load` and similar loaders. |
| `open-redirect` | An HTTP redirect target. |
| `plaintext-credential-storage` | A parameter named like a password stored in a database without hashing. Medium confidence, since a name is a hint. |
| `exploitable-vulnerability` | An API affected by an advisory of a vulnerable requirement, see Dependencies. |

Each flow is judged before it is reported. A dominating guard that proves the value
safe (`isdigit()`, membership in a constant collection, equality with a constant, a
numeric value proven by `int()`, `len()` or bounded arithmetic, a validator such as
`re.fullmatch`) refutes it and nothing is reported. A guard that only mentions the value,
or an authorization decorator such as `login_required`, makes it a hotspot reported at
medium confidence. The verdict and its evidence are in the finding's metadata.

### Dangerous API usage

| Rule | Reported call |
|---|---|
| `dangerous-eval` | `eval` or `exec`, whatever name the file gives them. |
| `weak-crypto` | `hashlib.md5`, `hashlib.sha1` and other broken algorithms. |
| `debug-enabled` | `app.run(debug=True)` on a Flask application. |
| `missing-timeout` | A Requests or httpx call without a `timeout`. |

### Secrets

One finding per literal, with a redacted preview and never the secret itself, in Python
sources and in configuration files.

| Rule | Confidence | Trigger |
|---|---|---|
| `hardcoded-secret` | high | A provider-specific format: AWS, GitHub, Slack, Stripe, Google, private keys, JWTs, SendGrid, Twilio. |
| `hardcoded-credential` | medium | A credential-like name (`password`, `token`, `api_key`, `app.config['SECRET_KEY']`, …) bound to a real value. Placeholders are excluded. |
| `high-entropy-string` | low | An opaque high-entropy token. |

### Dependencies

| Rule | Trigger |
|---|---|
| `vulnerable-dependency` | A requirement allows a version affected by an advisory, reported at its line. |
| `reachable-vulnerability` | A call in the project to an API the advisory affects. |
| `exploitable-vulnerability` | Attacker-controlled data reaches such a call. Critical. |
| `denied-dependency` | A package the policy denies. |
| `unpinned-dependency` | A requirement without an exact pin when the policy requires pins. |

## Reports

`--format` accepts `text`, `json` and `sarif`.

`--format text` prints one line per finding, `path:line:column: severity rule: message`,
then the count and the coverage line. Paths are relative to the checked directory, or to
the directory of the checked file; a path outside it is printed as it is.

`--format json` prints one document:

```json
{
  "schema_version": 1,
  "tool": {"name": "coretrace-python-analyzer", "version": "0.1.0"},
  "root": "/home/me/project",
  "findings": [
    {
      "rule_id": "sql-injection",
      "message": "SQL injection: http input reaches python.sqlite3.connect.cursor.execute",
      "severity": "high",
      "confidence": "high",
      "location": {"path": "app.py", "line": 50, "column": 21, "end_line": 50, "end_column": 60},
      "function": "user",
      "metadata": {"source": "python.flask.request.args", "verdict": "vulnerability"}
    }
  ],
  "coverage": {
    "files": 2, "files_analysed": 2, "functions": 12, "functions_analysed": 12,
    "details": [{"path": "app.py", "status": "analysed", "functions": 9, "analysed": 9}]
  }
}
```

`root` is the directory the paths are relative to.

`--format sarif` prints a SARIF 2.1.0 log, one run with the tool, its rules and one
result per finding. The root is declared once as the `SRCROOT` original URI base and
every location under it is relative to that base, which is what code scanning services
need to attach results to files:

```bash
coretrace-python-analyzer --check src/ --format sarif > report.sarif
```

## Dependencies, advisories and policy

The bundled `sample-advisories` plugin ships a small offline database. A real feed stays
offline too: convert a public OSV dump once, then read it at every check.

```bash
coretrace-python-analyzer --import-advisories osv-dump.zip advisories.json
coretrace-python-analyzer --check src/ --advisories advisories.json
```

A directory check reads `advisories.json` at the project root and every file passed
with `--advisories`; a local entry wins over a plugin's for the same advisory. The file
lists advisories with the package, the vulnerable version range and, optionally, the
affected APIs that feed reachability and correlation:

```json
{
  "schema": 1,
  "advisories": [
    {
      "id": "CVE-2020-1747",
      "package": "pyyaml",
      "vulnerable": "<5.4",
      "summary": "yaml.load can execute arbitrary code from untrusted documents",
      "severity": "critical",
      "affected_symbols": ["python.yaml.load", "python.yaml.full_load"],
      "aliases": ["GHSA-8q59-q68h-6hv4"]
    }
  ]
}
```

A `coretrace-policy.toml` at the root, or the file passed with `--policy`, denies
packages, requires pins and lists accepted advisories whose findings are dropped:

```toml
[dependencies]
deny = ["pycrypto"]
require_pinned = true

[advisories]
ignore = ["CVE-2020-1747"]
```

`--sbom PATH` writes a CycloneDX 1.5 bill of materials: one component per requirement
with its package URL, and the advisories affecting them as vulnerabilities.

```bash
coretrace-python-analyzer --check src/ --sbom sbom.json --policy security/policy.toml
```

## Large projects

`--cache DIR` keeps the results of a directory check on disk, one entry per module,
keyed by the module's source, the tool and plugin versions, the security models, the
advisories, the dependency graph and the modules it imports. On the next run an unchanged
module is served from the cache, so editing one file re-analyses that file and its
importers only. Entries are plain data; an unreadable entry is recomputed.

`--jobs N` analyses independent modules in `N` processes. Modules are scheduled imports
first, so the result is the same whatever `N`.

```bash
coretrace-python-analyzer --check src/ --cache .coretrace --jobs 4
```

## Plugins

The package ships 26 plugins, loaded by default. Security models for the standard library
and the supported frameworks: `python-stdlib-models`, `flask-models`, `fastapi-models`,
`django-models`, `sqlalchemy-models`, `http-client-models`, `credential-models` and
`cli-models`. Taint detectors: `command-injection`, `sql-injection`, `path-traversal`,
`ssrf`, `xss`, `insecure-deserialization`, `open-redirect` and `plaintext-credentials`.
Dangerous API detectors: `dangerous-eval`, `weak-crypto`, `flask-debug` and
`missing-timeout`. Secret scanners: `hardcoded-secrets` for Python sources and
`config-secrets` for configuration files. Dependency checks: `sample-advisories`,
`vulnerable-dependency`, `reachable-vulnerability` and `dependency-policy`.

`--plugins DIR` loads your own plugins on top, `--no-bundled-plugins` runs without the
shipped ones. Writing a plugin, a model for another framework or a detector for another
rule, is described in [plugins.md](plugins.md).

```bash
coretrace-python-analyzer --check src/ --plugins ./coretrace-plugins
coretrace-python-analyzer --check src/ --no-bundled-plugins --plugins ./coretrace-plugins
```

## Continuous integration

The exit status gates the job and the SARIF report feeds code scanning. On GitHub
Actions:

```yaml
- run: pip install coretrace-python-analyzer
- run: coretrace-python-analyzer --check src/ --format sarif > coretrace.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: coretrace.sarif
```

Add `--cache` on a directory restored between runs to analyse only what changed.

## From Python

```python
from pathlib import Path
from coretrace_python import engine

analysis = engine.analyze_project(Path("src"), [engine.BUNDLED_PLUGINS])
for finding in analysis.findings:
    print(finding.rule_id, finding.span.source_id, finding.span.start_line, finding.message)
print(analysis.coverage.summary())
```

`analyze_project` accepts the same options as the command line (`cache`, `jobs`,
`advisory_files`, `policy_file`). `analyze_file` checks one `SourceFile` loaded through
`SourceManager`.

## Supported syntax

Inside functions: parameters with defaults, keyword-only and star forms, decorators,
assignments to names, attributes, items and unpacked tuples, augmented and chained
assignment, list, tuple, set and dict literals with unpacking, f-strings, slices,
boolean operators, chained comparisons, keyword and starred arguments, `with`, `assert`,
`try`/`except`/`else`/`finally`, `await`, `yield`, `if`, `while` and `for` with their
`else` clauses, `break`, `continue`, `raise` with `from`, conditional expressions,
comprehensions, lambdas, nested functions and classes, `global`, `nonlocal`, `del` and
`match` with every pattern kind. `finally` is modelled on the normal path only and a
`nonlocal` write stays inside the nested function. Methods of module-level classes are
analysed like functions.

## Looking at the intermediate representation

```bash
coretrace-python-analyzer --emit-ir example.py
coretrace-python-analyzer --emit-ir --ssa example.py
```

Each function is printed as its control-flow graph, one block per basic block ending in
an explicit terminator. With `--ssa`, locals become numbered values and merges get `phi`
instructions. Names are resolved to canonical symbols through imports and builtins, so
`from os import system as run` still shows a call to `python.os.system`.
