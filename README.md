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

## Emit PyIR

```bash
coretrace-python-analyzer --emit-ir example.py
# or, without installing:
PYTHONPATH=src python -m coretrace_python --emit-ir example.py
```

Currently supported inside functions: arguments, assignments, names, constants, binary
operations, unary operations, comparisons, calls, attribute access, indexing, returns,
`if`/`elif`/`else`, `while`, `for`, `break`, `continue` and `raise`. Each function is
emitted as its control-flow graph: one block per basic block, ending in an explicit
terminator (`branch`, `jump`, `return`, `raise`, `for_next`).
Unsupported syntax produces a source-located diagnostic and a non-zero exit status.

Names are resolved to canonical symbols through lexical scopes, imports and builtins.
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
