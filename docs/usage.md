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
usage or analysis error, so the command can gate a pipeline as it is. `--fail-on high`
keeps reporting every finding but fails only from that severity up.

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
| `--vex PATH` | Write an OpenVEX document to `PATH`: whether each advisory affecting a requirement affects the project. |
| `--advisories FILE` | Read a local advisory file in addition to `advisories.json` at the root. Repeatable. |
| `--policy FILE` | Apply this dependency policy instead of `coretrace-policy.toml` at the root. |
| `--import-advisories SRC OUT` | Convert an OSV dump into the local advisory file `OUT`, then exit. |
| `--fail-on SEVERITY` | Exit with status 1 only when a finding of this severity or above was reported: `info`, `low`, `medium`, `high` or `critical`. Default: any finding. |
| `--baseline PATH` | The accepted findings: written on the first run, then only findings not recorded there fail the check. |
| `--emit-ir` | Print the intermediate representation of `path` instead of checking it. |
| `--ssa` | With `--emit-ir`, print the static single assignment form. |
| `--help` | Show the options and exit. |

`--cache`, `--jobs`, `--sbom`, `--vex`, `--advisories` and `--policy` apply to a directory check.

## What is analysed

Given a directory, every `.py` file below it is a module of one project, named after
its package (`app/views.py` is `app.views`). Hidden directories, `node_modules`,
`__pycache__`, `build`, `dist` and any virtual environment, recognised by its
`pyvenv.cfg` whatever its name, are skipped. Dependency files at the root
(`requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`) are read into a
dependency graph. Configuration files under the root (`.env`, YAML, TOML, JSON, INI,
properties) are scanned for secrets.

Functions and methods are analysed, and so are the module body and the bodies of
top-level classes, as the functions `<module>` and `Cls.<body>`: `application =
get_asgi_application()` in `asgi.py` or `email = forms.EmailField()` in a form class are
calls the analyzer sees, and a module-level `os.system(input())` is a finding in `<module>`.
A function using syntax outside the supported subset is reported as an
`unsupported-syntax` note and the other functions are still analysed; a file Python
itself cannot parse is reported as a `syntax-error`. The coverage line and the JSON
report's per-file detail tell "no findings" from "nothing analysed".

Taint follows values between functions and across files through function summaries,
into objects (containers, attributes, instances of the project's own classes) and through
closures. Flask, FastAPI, Django, aiohttp, Tornado and Bottle route handlers, class-based views
and registered URL patterns receive HTTP input, and a method a handler class inherits
from its framework base, `self.get_argument` or `self.request`, denotes the base's; click and Typer commands receive `argv` input; `input()`,
`sys.argv`, environment variables, the output of local processes and the responses of
HTTP clients are further sources. The first three are operator-controlled: a command-line
tool opens the paths it is given, a command or a path built from the environment is the
operator's own doing, and a path read from a local process is not a traversal, so those
sources do not carry the corresponding kinds; a downloaded script piped into a shell
stays a command injection.

## Rules

Findings carry a rule id, a severity (`critical`, `high`, `medium`, `low`) and a
confidence (`high`, `medium`, `low`).

### Taint flows

Reported when attacker-controlled data reaches a sensitive call without passing through
a sanitizer for that kind of sink. The sanitizer may also sit inside a project function
the data goes through, like a helper that escapes before it answers, or a view that
redirects to `reverse(...)`. It then protects every caller, on every path through the
function where it is called. What a function stores into an object or a `nonlocal`
variable is not treated that way yet.

| Rule | Reached sink |
|---|---|
| `command-injection` | Shell or process execution (`os.system`, `subprocess` with a string, …). |
| `code-injection` | The code `eval` or `exec` runs; the globals and locals passed with it are data. `dangerous-eval` reports every such call, this rule the ones attacker input reaches. |
| `sql-injection` | A database statement (`cursor.execute`, SQLAlchemy `text`, Django `raw`, …). Parameters of a parameterised query are not statements. |
| `nosql-injection` | A NoSQL query, such as a MongoDB filter, given attacker input that may hold a structure: a JSON body giving `{"$ne": null}` matches any value. The input that may hold a structure is JSON, the raw bodies a `json.loads` decodes, files, WebSocket messages and standard input. Text cannot hold an operator: form fields, query parameters, headers, cookies, URL parameters, the command line, the environment, and an entry-point parameter annotated with scalars (`str`, `int`, `Optional[str]`, `Annotated[str, Query()]`, `list[str]`, …), which FastAPI validates. A Django, REST framework, aiohttp or tornado view reads a request object: its text attributes (`GET`, `POST`, `headers`, `query_params`, `query`, `match_info`, `arguments`, …) and the URL parameters after it are text, its body, files and `data` are not. Limits: a helper function the request is passed to reads it as a whole; the keys of a dict are not followed, so a string concatenated into `$where` is not reported. The analyzer ships no NoSQL sink: model plugins declare them. |
| `path-traversal` | A file system path (`open`, `send_file`, `os.remove`, …). |
| `ssrf` | The URL of an HTTP client request (Requests, httpx, `urllib`), by position or as `url=`; the body, headers and query parameters are not the destination. How `+` and f-strings build the URL can prove part of its destination. When constant text fixes `scheme://host` and ends the authority with `/`, `?` or `#` before any input (`"https://api.example.com/users/" + id`, or a module-level string bound once and never rebound), the flow is a hotspot: the input still chooses the path, which may reach a sensitive resource, and a redirect may lead elsewhere. With the path fixed too, the input reaching the query or fragment only, and the call disabling redirects (`allow_redirects=False`, `follow_redirects=False`), the destination is fixed and the flow is refuted. Anything unproven stays a vulnerability: a base of unknown value (imported, a call result), a constant leaving the authority open (`"https:/"`, no `/` after the host, a variable port), `urljoin`, `%`, `format`, a URL built in a helper function. |
| `xss` | An HTTP response body built without escaping. A Django template rendered by `render_to_string` escapes, where the analyzer can establish it (below). |
| `insecure-deserialization` | `pickle`, `marshal`, `dill`, `jsonpickle`, `shelve`, and the YAML loaders (`yaml.load`, `load_all`, `full_load`, `unsafe_load` and their several-document versions); `yaml.load` and `load_all` given a safe loader (`SafeLoader`, `BaseLoader`) are not. |
| `open-redirect` | An HTTP redirect target, judged on the destination a browser resolves from the target's constant text, as `+` and f-strings build it. A reference on the current site keeps the browser there, where any further redirect is the project's own code, analysed on its own, so the flow is refuted. Such a reference is `/` followed by a character that is not a slash, a backslash, a space or a control character (`"/profile/" + id`), `?`, `#`, or a relative path whose first segment ends in the text without a `:`. A fixed absolute host (`"https://example.com/" + path`) sends the browser there, but the input chooses the path, where that host may redirect again: a hotspot. Anything else stays a vulnerability. That covers `"/" + next`, since `//evil.com` is another host, a host left open, a base of unknown value and a target built in a helper function. |
| `plaintext-credential-storage` | A parameter named like a password stored in a database without hashing. Medium confidence, since a name is a hint. |
| `exploitable-vulnerability` | An API affected by an advisory of a vulnerable requirement, see Dependencies. |

Each flow is judged before it is reported. A dominating guard that proves the value
safe (`isdigit()`, membership in a constant collection, equality with a constant, a
numeric value proven by `int()`, `len()` or bounded arithmetic, a validator such as
`re.fullmatch`) refutes it and nothing is reported. A hotspot is reported at medium
confidence. Two things make a flow a hotspot:

- A guard that examines the data without proving it safe. That covers a test of the value
  itself (`if cmd:`, `len(cmd) < 10`), of the same attribute, or of a method called on
  it (`form.is_valid()`).
- An authorization decorator such as `login_required`.

A guard that reads another attribute of the object the data comes from is no guard of
that data. `if request.method == 'POST':` before `os.system(request.POST['cmd'])` leaves
a vulnerability. When the flow passes the object whole, to the sink or to a function,
a guard on any of its attributes still counts. The verdict and its evidence are in the
finding's metadata.

Django's `render_to_string(name, context)` returns HTML in which autoescaping escaped
every variable, so data reaching a response through it is no `xss`, if the template really
escapes. On a directory check, the analyzer reads the project's templates to decide it.

It establishes escaping only when all of the following hold:

- It finds every template of that name under a `templates` directory, by the path Django
  uses (`app/page.html`), and everything those templates extend or include.
- None of them marks output safe: `|safe`, `|safeseq` or `{% autoescape off %}`.
- None of them uses a tag or filter beyond Django's own, or loads a library beyond its
  built-ins (`static`, `i18n`, `l10n`, `tz`, `cache`, `humanize`).
- None of them places a variable where HTML escaping does not protect it: a `<script>`
  or `<style>` block, an event handler (`onclick="…"`), a `style` attribute, a URL
  attribute not fixed by a relative or `http(s)://host/` prefix, an unquoted attribute,
  or an attribute name.
- No Python file of the project sets `autoescape` to `False`.

The analyzer never assumes escaping where it cannot read the template. That covers a
template named by an expression, a template found through a `DIRS` entry not named
`templates`, one shipped by an installed package, one rendered through `get_template`,
and Flask's Jinja2 templates. The flow is then reported as before. A single-file check
reads no template.

### Dangerous API usage

| Rule | Reported call |
|---|---|
| `dangerous-eval` | `eval` or `exec`, whatever name the file gives them. |
| `weak-crypto` | `hashlib.md5`, `hashlib.sha1` and other broken algorithms. |
| `debug-enabled` | `app.run(debug=True)` on a Flask application. |
| `missing-timeout` | A Requests or httpx call without a `timeout`. |
| `insecure-tls` | `verify=False` on a Requests or httpx call, or `ssl._create_unverified_context()`. |
| `unsafe-xml` | A standard-library or lxml XML parser, which expands entities; `defusedxml` is the safe replacement. |
| `unsafe-archive-extraction` | `tarfile` or `zipfile` extraction, or `shutil.unpack_archive`, without a member `filter`. |
| `insecure-temp-file` | `tempfile.mktemp`, which names a file without creating it. |
| `weak-random` | A `random` function whose result is assigned to a credential-like name, or produced by a function named like one. Medium confidence. |

### Secrets

One finding per literal, with a redacted preview and never the secret itself, in Python
sources and in configuration files.

| Rule | Confidence | Trigger |
|---|---|---|
| `hardcoded-secret` | high | A provider-specific format: AWS, GitHub, Slack, Stripe, Google, private keys, JWTs, SendGrid, Twilio. |
| `hardcoded-credential` | medium | A credential-like name (`password`, `token`, `api_key`, `app.config['SECRET_KEY']`, …) bound to a real value. Placeholders are excluded. Low confidence in test code, fixtures and template files such as `.env.example`, with the context in the metadata. |
| `high-entropy-string` | low | An opaque high-entropy token. Hex digests (MD5, SHA-1, SHA-256, SHA-512 lengths, or a name such as `hash`, `checksum`, `commit`), subresource-integrity hashes (`sha512-…`) and character-set constants are not secrets unless a credential name says so. |

### Dependencies

| Rule | Trigger |
|---|---|
| `vulnerable-dependency` | A requirement allows a version affected by an advisory, reported at its line. |
| `reachable-vulnerability` | A call in the project to an API the advisory affects, or a read of an entry point marked `read`. |
| `exploitable-vulnerability` | Attacker-controlled data reaches such a call. Critical. |
| `denied-dependency` | A package the policy denies. |
| `unpinned-dependency` | A requirement without an exact pin when the policy requires pins. |

## Suppressing a finding

A finding whose line carries a `# coretrace: ignore` comment is suppressed. With a list
of rules, only those are:

```python
data = yaml.load(text)  # coretrace: ignore[insecure-deserialization]
```

The comment also works in requirements files, where a line
`pyyaml==5.3.1  # coretrace: ignore[vulnerable-dependency]` silences that requirement's
finding. Suppressed findings are kept apart: the text report counts them, the JSON report
lists them under `suppressed`, the SARIF log marks them as suppressed in source, and
they never affect the exit status.

## Adopting the analyzer on an existing code base

A repository with known findings starts from a baseline:

```bash
coretrace-python-analyzer --check src/ --baseline coretrace-baseline.json
```

The first run writes the file with every current finding and passes. Later runs set the
recorded findings apart and fail only on new ones. A finding is recognised by its file,
its rule, its function and the text of its line, not by its line number, so code inserted
above it does not make it new; a change to the line itself does. Commit the file and
shrink it as findings are fixed: an entry without a matching finding is simply unused.
Baselined findings are counted in the text report, listed under `baselined` in the JSON
report and marked `baselineState: unchanged` in the SARIF log, where new results are
marked `new`.

## Reports

`--format` accepts `text`, `json` and `sarif`.

`--format text` prints one line per finding, `path:line:column: severity rule: message`,
then the count and the coverage line. Paths are relative to the checked directory, or to
the directory of the checked file; a path outside it is printed as it is.

`--format json` prints one document:

```json
{
  "schema_version": 1,
  "tool": {"name": "coretrace-python-analyzer", "version": "0.14.0"},
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

A directory check also lists, in `tool.components`, what the result was produced with
besides the engine and the sources: each plugin it loaded, by manifest name and version,
and each advisory file it read, by path (relative to the root when under it). Each
component carries the SHA-256 digest of its content, so a result can be traced to the
exact advisory data it used and reproduced. A plugin's digest covers its directory as the
cache fingerprints it, bytecode and hidden files left out; a file's digest covers its
bytes. A single-file check lists no components.

```json
"tool": {
  "name": "coretrace-python-analyzer", "version": "0.14.0",
  "components": [
    {"kind": "plugin", "name": "curated-advisories", "version": "2026.09.25", "digest": "sha256:…"},
    {"kind": "advisories", "name": "advisories.json", "digest": "sha256:…"}
  ]
}
```

A finding about an advisory names, in its `advisory_source` metadata, where the advisory
comes from. For a plugin this is `name@version`, and for an advisory file its path. When
several sources define the same advisory, it names the one whose definition is used, as
the next section describes.

`--format sarif` prints a SARIF 2.1.0 log, one run with the tool, its rules and one
result per finding. The root is declared once as the `SRCROOT` original URI base and
every location under it is relative to that base, which is what code scanning services
need to attach results to files. The components of a directory check are the tool's
`extensions`, their kind and digest in `properties`:

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
lists advisories with the package, the vulnerable version range (a specifier, or several
separated by `||` when several release series are affected) and, optionally, the
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
      "affected_symbols": ["python.yaml.constructor.FullConstructor.construct_python_object_apply"],
      "entry_points": [
        {
          "symbol": "python.yaml.full_load",
          "justification": "FullLoader uses FullConstructor (commit 5080ba5)",
          "conditions": [
            {"kind": "semantic", "text": "the document carries a python/object/apply tag"}
          ]
        },
        {
          "symbol": "python.yaml.load",
          "justification": "same path when Loader is FullLoader",
          "conditions": [
            {"kind": "argument", "text": "Loader is FullLoader, the default", "argument": "Loader", "position": 1,
             "values": ["python.yaml.FullLoader", "python.yaml.loader.FullLoader"], "default": true},
            {"kind": "semantic", "text": "the document carries a python/object/apply tag"}
          ]
        }
      ],
      "modules": ["yaml"],
      "aliases": ["GHSA-8q59-q68h-6hv4"]
    }
  ]
}
```

`affected_symbols` are the functions the fix changed; `entry_points` the public APIs
through which a project reaches them, each with the justification that ties it to the
fix — the commit, or the call path — and the `conditions` under which it is affected. A
call to either kind of symbol is reachable. `modules` names the top-level modules the
package installs, so the analyzer can tell an imported package from a merely required
one; it defaults to the package name.

An entry point marked `"read": true` is an attribute whose getter runs the affected code,
such as a request body parsed on first access
(`{"symbol": "python.flask.request.form", "justification": "…", "read": true}`): reading
it is reachable, called or not — `request.form['name']`, `for key in request.form`,
`request.form.get('name')` all read it. A function reading it several times is reported
once, where it first reads it.

Most vulnerabilities need attacker input in one argument: the path `send_from_directory`
serves, not its `download_name`; the URL `requests.get` fetches, not its body. An entry
point may name them in `attacker_arguments`, by keyword `argument` and, when it may be
passed positionally, by `position`, counted as for argument conditions; `"variadic": true`
extends a position to every later one, as `safe_join(directory, *pathnames)` takes
(`{"position": 1, "variadic": true}`). A call is then exploitable only when attacker
input reaches one of them, `"attacker_arguments": [{"argument": "url", "position": 0}]`
for `requests.get`; attacker input in another argument leaves it reachable. An argument
unpacked with `*args` or `**kwargs` may fill any of them: like an argument condition it
leaves undecided, it does not rule the call out, so it counts, and a wrapper forwarding
`*args, **kwargs` to the entry point still reaches it. An entry point without
`attacker_arguments` is exploitable through any argument.

An `argument` condition is decided at each call. It names the argument by keyword and,
when it may be passed positionally, by `position` (counted from 0, the receiver of a
method excluded); `values` are what makes the call affected, written as the analyzer
sees arguments: a symbol by its canonical name (`python.yaml.FullLoader`, and every
spelling a project may use, such as `python.yaml.loader.FullLoader`), a constant as
Python writes it (`True`, `None`, `'/static'`); `default` says an absent argument means
an affected value. A call passing another known value does not reach the vulnerability;
a call passing a variable, or unpacking `*args` or `**kwargs`, leaves the condition
pending review. A `semantic` condition — the document's tags, the platform, the
template's origin — cannot be decided and is always pending review, never dropped.

Every dependency finding records the highest level of evidence established in its
`level` metadata: `declared` (the requirement allows a vulnerable version), `imported`
(a module of the package is imported somewhere), `reachable` (an entry point or affected
symbol is called, or an entry point marked `read` is read) or `exploitable` (attacker
input reaches it). The last two carry
`entry_point`, `justification`, `conditions`, and which of them the call meets
(`conditions_met`) or leaves to review (`conditions_pending_review`). A requirement whose
entry points are only called with arguments that contradict a condition stays
`imported`, and its finding lists those calls in `ruled_out`
(`app.views:12 python.yaml.load(Loader=python.yaml.SafeLoader)`), the evidence that
they do not reach the vulnerability.

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
with its package URL, and the advisories affecting them as vulnerabilities. Its tools
list the analyzer and the components of the check, each with its SHA-256 hash: a plugin
as an `application`, an advisory file as `data`.

```bash
coretrace-python-analyzer --check src/ --sbom sbom.json --policy security/policy.toml
```

`--vex PATH` writes an OpenVEX 0.2.0 document with one statement per advisory affecting
a requirement. In each statement, the required package is a subcomponent of the project,
identified as `pkg:generic/<directory>`. The status follows from the evidence of the
check, including findings the policy accepts or a comment suppresses:

| Status | When |
|---|---|
| `affected` | The project's code reaches the vulnerable code. The notes give each place and its level, `reachable` or `exploitable`. |
| `not_affected` | Justified as `vulnerable_code_not_in_execute_path`, only when all of these hold: the advisory names entry points, no code of the project reaches them, every file and function was analysed, and a lock file (`uv.lock` or `poetry.lock`) shows that no other package requires the vulnerable one. The impact statement names the entry points and any calls ruled out by their arguments. |
| `under_investigation` | Anything else. The notes say which condition failed. |

`not_affected` needs the lock-file check because the analyzer reads the project's code,
not the code of installed packages. A framework calling the vulnerable function on the
project's behalf would go unseen. Without a lock file, a package is never
`not_affected`. The document's `@id` derives from its statements, so two runs with the
same result share it; its `author` is `Unknown Author`, as OpenVEX tools write when they
cannot know it. Its `tooling` names the analyzer and each component with its digest
(`coretrace-python-analyzer 0.14.0; curated-advisories 2026.09.25 (sha256:…)`), so the
`@id` changes with the advisory data a statement was decided with.

## Large projects

`--cache DIR` keeps the results of a directory check on disk, one entry per module,
keyed by the module's source, the tool version, every file of every plugin directory
(code, manifest and data alike), the security models, the advisories, the dependency
graph and the modules it imports. On the next run an unchanged
module is served from the cache, so editing one file re-analyses that file and its
importers only. Entries are plain data; an unreadable entry is recomputed.

`--jobs N` analyses independent modules in `N` processes. Modules are scheduled imports
first, so the result is the same whatever `N`.

```bash
coretrace-python-analyzer --check src/ --cache .coretrace --jobs 4
```

## Performance

Measured on one core of a laptop, single process, cold start, with the bundled plugins
(September 2026):

| Project | Python lines | Functions | Time | Peak memory |
|---|---:|---:|---:|---:|
| healthchecks (Django application) | 45 000 | 2 566 | 7 s | 107 MB |
| rich (library) | 52 000 | 1 198 | 6 s | 106 MB |
| wagtail (Django CMS) | 273 000 | 12 146 | 85 s | 461 MB |

Time grows a little faster than linearly with the size of the project, because the
interprocedural summaries are iterated to a fixpoint over the module graph. A warm
`--cache` brings an unchanged healthchecks to about one second, `--jobs 4` saves a
quarter of the cold time at the cost of one process's memory per job. The
`healthchecks` repository is part of the regression corpus, so the analysis time of a
real 45 000-line project is exercised on every change.

## Plugins

The package ships 35 plugins, loaded by default. Security models for the standard library
and the supported frameworks: `python-stdlib-models`, `flask-models`, `fastapi-models`,
`django-models`, `aiohttp-models`, `tornado-models`, `bottle-models`, `sqlalchemy-models`, `db-driver-models` (aiopg,
asyncpg, psycopg2, PyMySQL), `http-client-models`, `credential-models` and `cli-models`. Taint detectors: `command-injection`, `sql-injection`, `path-traversal`,
`ssrf`, `xss`, `insecure-deserialization`, `open-redirect` and `plaintext-credentials`.
Dangerous API detectors: `dangerous-eval`, `weak-crypto`, `flask-debug`,
`missing-timeout`, `insecure-tls`, `unsafe-xml`, `unsafe-archive-extraction`,
`insecure-temp-file` and `weak-random`. Secret scanners: `hardcoded-secrets` for Python sources and
`config-secrets` for configuration files. Dependency checks: `sample-advisories`,
`vulnerable-dependency`, `reachable-vulnerability` and `dependency-policy`.

`--plugins DIR` loads your own plugins on top, `--no-bundled-plugins` runs without the
shipped ones. Writing a plugin, a model for another framework or a detector for another
rule, is described in [plugins.md](plugins.md).

```bash
coretrace-python-analyzer --check src/ --plugins ./coretrace-plugins
coretrace-python-analyzer --check src/ --no-bundled-plugins --plugins ./coretrace-plugins
```

### Your own validation layer

A code base that already validates its input has functions the analyzer cannot know are
safe: a `clean()` that returns its argument looks, from its body, like a function that
passes taint through. Declare them in a model plugin by their project symbol,
`python.<module>.<function>`, and the analyzer takes your word over what it derived:

```python
from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Sanitizer, TaintKind, Validator


class HouseModels(ModelPlugin):
    name = "house-models"
    models = (
        # the result of app.validation.clean is safe for commands, whatever the body does
        Sanitizer(SymbolId("python.app.validation.clean"), TaintKind.COMMAND),
        # a flow behind ``if app.validation.is_slug(value):`` is refuted
        Validator(SymbolId("python.app.validation.is_slug")),
    )
```

## Continuous integration

The exit status gates the job and the SARIF report feeds code scanning. On GitHub
Actions:

```yaml
- run: pip install coretrace-python-analyzer
- run: coretrace-python-analyzer --check src/ --fail-on high --format sarif > coretrace.sarif
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
comprehensions, lambdas, nested functions and classes, `global`, `nonlocal`, `del`,
assignment expressions (`(y := f(x))`, laid out as an assignment before the statement),
`yield from`, starred assignment targets (`first, *rest = items`), class keyword arguments
such as `metaclass=`, `with` targets of any assignable form and `match` with every
pattern kind. `finally` is modelled on the normal path only. A
`nonlocal` write made by a nested function flows back to the enclosing variable when the
enclosing function calls that nested function directly by name; a nested function passed
around and called elsewhere keeps its writes to itself. Methods of module-level classes are
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
