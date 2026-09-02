# CoreTrace Python Analyzer

A standalone, Python-specific static analysis frontend for CoreTrace.

The analyzer loads source through a source manager, adapts parsed Python into a
parser-independent high-level representation (PyHIR), and lowers a deliberately small
language subset to deterministic PyIR. CFG construction, SSA, data-flow, and security rules
are intentionally deferred.

```text
Python source -> SourceManager -> parser -> PyHIR -> semantic imports -> PyIR
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

## Emit PyIR

```bash
coretrace-python-analyzer --emit-ir example.py
# or, without installing:
PYTHONPATH=src python -m coretrace_python --emit-ir example.py
```

Currently supported inside functions: arguments, assignments, names, constants, binary
operations, unary operations, comparisons, calls, attribute access, indexing, and returns.
Unsupported syntax produces a source-located diagnostic and a non-zero exit status.

Module-level imports are resolved to canonical symbols. Import aliases do not change an
API's identity, so all of the following resolve to `python.os.system`:

```python
import os
from os import system
from os import system as run
```

Relative and wildcard imports are not supported yet and produce source-located diagnostics.
