# Writing a plugin

A plugin is a directory holding a `plugin.toml` manifest and a Python module with one
class. The analyzer searches `--plugins DIR` recursively for manifests, imports each
module by path and instantiates the class. The plugins shipped with the package live
under `coretrace_python/bundled/` and are written the same way; they are the reference
for every kind of plugin described here.

```text
coretrace-plugins/
└── sensitive_logging/
    ├── plugin.toml
    └── sensitive_logging.py
```

```bash
coretrace-python-analyzer --check src/ --plugins ./coretrace-plugins
```

## The manifest

```toml
name = "sensitive-logging"
version = "1.0.0"
plugin_api = ">=1,<2"
requires = ["ir.ssa"]
provides = ["vulnerability.sensitive-logging"]

[entrypoint]
module = "sensitive_logging"
class = "SensitiveLoggingPlugin"
```

| Field | Meaning |
|---|---|
| `name` | Unique plugin name, also used in cache keys. |
| `version` | The plugin's own version; changing it invalidates cached results. |
| `plugin_api` | The range of plugin API versions the plugin supports. The current API is version 1. |
| `requires` | Capabilities the plugin needs; a mismatch with the class's `requires` is a manifest error. |
| `provides` | Capabilities the plugin offers, for documentation and conflict detection. |
| `entrypoint` | The module file (without `.py`, next to the manifest) and the class in it. |

## Symbols

Every API is named by a canonical symbol: `python.` followed by the dotted path,
resolved through imports and aliases, so `python.os.system` covers `os.system`,
`from os import system` and `from os import system as run`. Calling a symbol denotes that
symbol, so a chain such as `sqlite3.connect(p).cursor().execute` is
`python.sqlite3.connect.cursor.execute`, and `app = Flask(__name__)` gives `app.route` the
symbol `python.flask.Flask.route`. Builtins are `python.builtins.<name>`. Symbols are
`SymbolId` values from `coretrace_python.semantic.symbols`.

## Kinds of plugin

Every plugin is a `Plugin` subclass (`coretrace_python.plugins`) with a class-level
`name` and a `requires` set of analyses; the base classes below fill in `analyze` for the
common cases.

### A detector of calls: `SymbolCallDetector`

Reports every call to one of a set of symbols, whatever name the file gives them.

```python
from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId


class SensitiveLoggingPlugin(SymbolCallDetector):
    name: ClassVar[str] = "sensitive-logging"
    rule_id: ClassVar[str] = "sensitive-logging"
    symbols: ClassVar[frozenset[SymbolId]] = frozenset({SymbolId("python.logging.debug")})
    severity: ClassVar[Severity] = Severity.LOW
    message_template: ClassVar[str] = "call to {symbol} may log sensitive data"
```

The shipped `dangerous-eval` and `weak-crypto` plugins are of this kind.

### A detector of taint flows: `TaintDetector`

Reports the flows of one taint kind that reach a sink and survive refutation. The
sources, sinks and sanitizers come from the model plugins, so a detector stays generic
and a new framework model makes every detector aware of it.

```python
from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import TaintDetector
from coretrace_python.taint import TaintKind


class CommandInjectionPlugin(TaintDetector):
    name: ClassVar[str] = "command-injection"
    rule_id: ClassVar[str] = "command-injection"
    kind: ClassVar[TaintKind] = TaintKind.COMMAND
    severity: ClassVar[Severity] = Severity.HIGH
    title: ClassVar[str] = "Command injection"
```

`confidence` defaults to high; a hotspot, a flow behind a guard that mentions the value
or an authorization decorator, is reported at medium. The taint kinds are `SQL`,
`COMMAND`, `HTML`, `PATH`, `SSRF`, `CODE`, `DESERIALIZATION`, `REDIRECT`, `ADVISORY`
(APIs affected by advisories) and `CREDENTIAL`, which only credential-named parameters
carry so that ordinary input reaching a database write is not a plaintext credential.

### Security models: `ModelPlugin`

Declares sources, sinks and sanitizers for a library or a framework. A model plugin
reports nothing by itself; the detectors consume what it declares.

```python
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import EntryPoint, Model, Sanitizer, Sink, Source, TaintKind


class BottleModels(ModelPlugin):
    name: ClassVar[str] = "bottle-models"
    models: ClassVar[tuple[Model, ...]] = (
        EntryPoint(SymbolId("python.bottle.route"), "http"),
        Source(SymbolId("python.bottle.request.query"), "http"),
        Sink(SymbolId("python.bottle.redirect"), TaintKind.REDIRECT),
        Sanitizer(SymbolId("python.bottle.html_escape"), TaintKind.HTML),
    )
```

| Model | Declares |
|---|---|
| `Source(symbol, label, kinds=ALL)` | A call or attribute whose value is attacker-controlled; `label` names it in messages (`http`, `stdin`, `argv`, `http-response`). `kinds` restricts what it can inject. |
| `Sink(symbol, kinds, positions=())` | A call dangerous for `kinds`; `positions` limits a kind to given argument indexes, as SQL sinks read the statement only. |
| `Sanitizer(symbol, kinds)` | A call whose result is safe for `kinds`. |
| `EntryPoint(symbol, label, kinds=ALL)` | A decorator or a class base whose functions receive their parameters as `label` input, such as `flask.Flask.route`. |
| `TypedParameter(symbol, label, kinds=ALL)` | A class whose annotated parameters carry `label` input, such as Django's `HttpRequest`. |
| `NamedParameter(pattern, label, kinds)` | A regular expression on parameter names; matching parameters carry `kinds`, as `password` carries `CREDENTIAL`. |
| `RouteRegistrar(symbol, argument, label, kinds=ALL, keyword=None)` | A call registering a view at argument `argument` (or `keyword`), such as Django's `path`; the view receives `label` input. |
| `SuffixSink(suffix, kinds, positions=())` | A sink matched by the end of the symbol, for methods of any class such as `objects.raw`. |
| `Validator(symbol, kinds=ALL, argument=0)` | A callable whose truth proves its argument safe, such as `re.fullmatch`; a flow guarded by it is refuted. |
| `AuthorizationGuard(symbol, label)` | A decorator or a condition restricting who reaches the code, such as `login_required`; a flow behind it is a hotspot. |

A model plugin may also carry `advisories`, a tuple of `Advisory` values
(`coretrace_python.dependency`) with the package, the vulnerable range and the affected
symbols, as the shipped `sample-advisories` plugin does. Requirements matching them are
reported, calls to the affected symbols become reachable vulnerabilities and tainted
calls become exploitable ones.

### Secret scanners: `SecretDetector`

Judges every string literal of the module, or every value of a configuration file,
against provider patterns, credential-like names and entropy.

```python
from typing import ClassVar

from coretrace_python.plugins import SecretDetector, SecretPattern
from coretrace_python.plugins.secrets import DEFAULT_CREDENTIAL_NAMES, DEFAULT_PATTERNS


class InternalSecrets(SecretDetector):
    name: ClassVar[str] = "internal-secrets"
    patterns: ClassVar[tuple[SecretPattern, ...]] = (
        *DEFAULT_PATTERNS,
        SecretPattern("acme", r"acme_[0-9a-f]{40}"),
    )
    credential_names: ClassVar[tuple[str, ...]] = (*DEFAULT_CREDENTIAL_NAMES, "acme_key")
```

`entropy_threshold`, `hex_entropy_threshold` and `minimum_length` tune the high-entropy
rule. Findings carry a redacted preview only.

### Project-wide checks: `ProjectPlugin`

Runs once per project after every module is analysed, with a `ProjectContext`: the
module graph, the dependency graph, every advisory the plugins and advisory files
contributed, the policy, the project root, and each module's imports and call graph. The
shipped `vulnerable-dependency`, `reachable-vulnerability` and `dependency-policy` plugins
are of this kind.

```python
from collections.abc import Sequence
from typing import ClassVar

from coretrace_python.findings import Finding
from coretrace_python.plugins import ProjectContext, ProjectPlugin


class RequirementsPresent(ProjectPlugin):
    name: ClassVar[str] = "requirements-present"

    def analyze_project(self, ctx: ProjectContext) -> Sequence[Finding]:
        return ()  # inspect ctx.dependencies, ctx.modules(), ctx.call_graph(module)
```

### Anything else: `Plugin`

Override `analyze(self, ctx: PluginContext)` and return findings. `ctx.module` is the
module, `ctx.functions` its analysable functions and `ctx.get(Analysis, function)`
any analysis result: `SSAAnalysis` (`coretrace_python.ir.ssa`) for the code,
`TaintAnalysis` (`coretrace_python.taint`) for the flows, `RefutationAnalysis`
(`coretrace_python.findings.refutation`) for their verdicts, `DependencyAnalysis`
(`coretrace_python.dependency`) for the requirements. List what you read in `requires`.

## Findings

A `Finding` (`coretrace_python.findings`) has a `rule_id`, a `message`, a `Severity`, a
`Confidence`, a `SourceSpan` (file, start and end line and column), the enclosing
`function` and string `metadata`. Rule ids are lower-case words joined by dashes.

## Testing a plugin

Load the plugin directory with the engine and check one source or one project:

```python
from pathlib import Path

from coretrace_python import engine
from coretrace_python.source import SourceManager

source = SourceManager().add_source("app.py", "import logging\n\ndef f(x):\n    logging.debug(x)\n")
findings = engine.check(source, [Path("coretrace-plugins")])
assert [f.rule_id for f in findings] == ["sensitive-logging"]
```

Pass `engine.BUNDLED_PLUGINS` too when the plugin relies on the shipped models.
