# CoreTrace Python Analyzer

A standalone static security analyzer for Python. It finds injection vulnerabilities by
following attacker-controlled data through the program, across functions, files, objects
and closures, and judges each flow against the guards on its path; it reports dangerous
API usage, secrets committed in sources and configuration, and vulnerable or forbidden
dependencies, correlated with the code that reaches them. It runs offline, on a file or a
whole project, with no runtime dependency.

```bash
pip install coretrace-python-analyzer
coretrace-python-analyzer --check src/ --format sarif > report.sarif
```

- [Usage guide](docs/usage.md): command line, rules, report formats, dependencies and
  advisories, cache and parallelism, continuous integration.
- [Writing a plugin](docs/plugins.md): models for another framework, detectors for
  another rule, secret patterns and project-wide checks.
- [Architecture](docs/architecture.md): the engine's design and its migration plan.

The pipeline: source manager, parser-independent high-level representation (PyHIR),
semantic resolution of imports and scopes, lowering to a small intermediate
representation (PyIR), control-flow graphs, SSA, data-flow and abstract interpretation,
interprocedural summaries, taint and refutation, then plugins and reporters.

## Development

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m mypy
python -m pytest
python -m ruff check .
```

The non-regression suite analyses the public repositories pinned in
[`tests/regression/repositories.toml`](tests/regression/repositories.toml) and compares
findings and coverage with the snapshots in `tests/regression/expected/`. It clones on
first use, needs the network and runs in its own CI job:

```bash
python -m pytest -m regression
CORETRACE_REGRESSION_UPDATE=1 python -m pytest -m regression   # record an intended change
```

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
