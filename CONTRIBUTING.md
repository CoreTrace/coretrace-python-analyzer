# Contributing to CoreTrace Python Analyzer

## Local setup

Python 3.11 or newer is required. Create a virtual environment and install the development dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m mypy
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
```

The [README](README.md#development) explains the separate network-dependent regression corpus. Update documentation when changing rules, reports or plugin contracts, and describe the checks you ran in your pull request. Keep changes focused and use an English Conventional Commit subject.

Report suspected vulnerabilities through [SECURITY.md](SECURITY.md) rather than a public issue.
