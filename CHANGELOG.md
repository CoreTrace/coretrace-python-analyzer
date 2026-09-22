# Changelog

## Unreleased

### Dependencies

- Advisories distinguish the `affected_symbols` a fix changed from the public `entry_points` through which they are reached, each justified and carrying `conditions` (checkable argument values, or `semantic` ones kept as pending review); `modules` names what the package installs. Every dependency finding records its evidence `level`: `declared`, `imported`, `reachable` or `exploitable`.
- A call to an API affected by several advisories of the pinned release reports every one of them, not the first listed.
- One advisory per identifier and package: a later contributor replaces an earlier one, so a curated feed refines the bundled sample, and the sample names the modules its packages install.
- A version specifier may be a union of ranges separated by `||`, as an advisory over several release series needs (`>=4.2,<4.2.28 || >=5.2,<5.2.11`); the OSV import produces one such advisory per package instead of one per range.

### Plugins

- Every plugin module is registered in `sys.modules` before it runs, so a single-file plugin may define a dataclass under `from __future__ import annotations` (#105).
- `ProjectPlugin.refine(ctx, findings)` lets a project plugin reclassify the findings of a run: severity, confidence and added metadata only, with `refined_by` and the original values recorded; anything else raises `RefinementError` (#106).

## 0.3.0 (2026-09-22)

### Plugins

- Two plugins may declare the same symbol: an identical model is registered once and sinks merge their kinds and positions; a real conflict names both plugins instead of failing the run on the first duplicate (#92).
- A plugin's entrypoint may be a package, `<module>/__init__.py`, so a plugin can split its tables across files and import them relatively (#93).
- The cache key covers every file of a plugin directory, not only `.py` and `.toml`, so rules or advisories shipped as data invalidate cached results when they change (#94).

### Analysis

- New taint kinds: `NOSQL` in `TaintKind.ALL`; `LOG` and `PII` outside it, carried only by the values a model marks, so a NoSQL-injection, log-injection or personal-data detector no longer has to share a kind with another rule (#96).

### Precision

- A `Sanitizer` declared on a function of the analysed project takes precedence over the summary derived from its body, in the same file and across files, so a code base can declare its own validation layer (#95).

## 0.2.0 (2026-09-06)

### Adoption in an existing repository

- Report paths are relative to the checked root; the JSON report carries the root and the SARIF log declares it as the `SRCROOT` URI base, so code scanning attaches alerts to files (#75).
- `# coretrace: ignore` and `# coretrace: ignore[rule, rule]` silence a finding on its line, in Python sources and requirements files; suppressed findings are counted, listed and marked in the reports (#76).
- `--baseline PATH` records the accepted findings on the first run and fails later runs on new findings only; findings are recognised by file, rule, function and line text, not line number (#77).
- `--fail-on SEVERITY` sets the exit status to 1 only from that severity up (#78).

### Analysis

- Assignment expressions, `yield from`, starred assignment targets, class keyword arguments and any assignable `with` target are supported; they used to reject whole files (#80, #86).
- A `nonlocal` write made by a nested function flows back to the enclosing function when it calls that function directly, the last documented approximation (#84).
- An attribute a class does not define resolves through its base, so `self.get_argument` in a Tornado handler and `self.request` in a Django class-based view denote the framework's; static methods called on the class resolve to the method and pass no receiver (#89).
- Route registrations are found inside functions such as `setup_routes(app: Application)`, and `await f()` denotes what `f()` denotes (#88).

### Detection

- New security models: aiohttp, Tornado, Bottle, and the aiopg, asyncpg, psycopg2 and PyMySQL drivers (#88, #89).
- New rules: `insecure-tls`, `unsafe-xml`, `unsafe-archive-extraction`, `insecure-temp-file` and `weak-random` (#90).

### Precision

- Hex digests, subresource-integrity hashes and character-set constants are no longer high-entropy secrets; credentials in test code and template files are reported at low confidence; `token_type`-like names are not credentials (#81, #82, #87).
- Redirect sinks read their target argument only, so `redirect("url-name", arg)` is not an open redirect (#83).
- Environment variables and process output are operator-controlled: they carry no command or path kinds, except a downloaded script piped into a shell (#87).
- A container literal passed to a sink is serialised, never rendered, so it carries no HTML (#89).

### Performance and corpus

- A module's functions are collected once; 25 to 30 percent faster on large projects, measured on healthchecks, rich and wagtail and recorded in the usage guide (#79).
- The regression corpus grows to 19 repositories, including healthchecks, dvpwa, pygoat, the FastAPI full-stack template, httpie and luigi (#79, #85).

### Packaging

- The Apache License 2.0 text ships with the repository and the wheel (#74).

## 0.1.0 (2026-09-04)

First release on PyPI: the analyzer with its 26 bundled plugins, the regression suite on 13 public repositories and the usage and plugin guides.
