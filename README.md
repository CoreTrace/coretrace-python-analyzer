# CoreTrace Python Analyzer

A standalone, Python-specific static analysis frontend for CoreTrace.

The first milestone parses Python and lowers a deliberately small language subset to a
deterministic, Python-aware intermediate representation (PyIR). CFG construction, SSA,
data-flow, and security rules are intentionally deferred.

## Development

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
pytest
```

## Emit PyIR

```bash
coretrace-python-analyzer --emit-ir example.py
# or, without installing:
PYTHONPATH=src python -m coretrace_python --emit-ir example.py
```

Currently supported inside functions: arguments, assignments, names, constants, binary
operations, unary operations, comparisons, calls, attribute access, indexing, and returns.
Unsupported syntax produces a source-located diagnostic and a non-zero exit status.

