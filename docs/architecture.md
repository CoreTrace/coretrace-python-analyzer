# Architecture of the Extensible Python Analysis Engine

## 1. Objective

The objective is to build an **extensible Python static analysis framework** in which the engine exposes every stage of its pipeline and allows plugins to hook into the appropriate layer.

The engine must not be limited to security. Security is a collection of plugins built on top of a generic analysis infrastructure.

The system should eventually support:

- vulnerability detection;
- syntactic rules;
- code quality analysis;
- bug detection;
- dependency analysis;
- secret detection;
- framework analysis;
- configuration analysis;
- false-positive reduction;
- custom enterprise rules;
- CLI, JSON, and SARIF report generation.

Core principles:

1. Intermediate representations are produced once and shared.
2. A plugin declares the analyses it depends on.
3. The engine computes analyses lazily whenever possible.
4. Analyses are organized as a **dependency DAG**, not as a simple rigid chain.
5. Plugins consume stable analysis results instead of accessing internal structures directly.
6. Expensive analyses, especially taint, call graph, and interprocedural analysis, are shared.
7. Plugins do not duplicate CFGs, IRs, or global results.
8. IR transformations and read-only analyses are kept separate.
9. The engine manages caching, dependencies, and analysis invalidation.
10. Framework models, detection engines, and proof engines are kept separate.

---

# 2. Overview

```text
                         Python Project
                              │
                              ▼
                        Source Discovery
                              │
                              ▼
                       Frontend (ast)
                              │
                              ▼
                            PyHIR
                              │
                    ┌─────────┼─────────┐
                    ▼         ▼         ▼
                  Scopes    Imports   Symbols
                    └─────────┼─────────┘
                              ▼
                             CFG
                              │
                              ▼
                         SSA / PyIR
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
             Data-flow    Call Graph   Abstract Value
                 │            │            │
                 └────────────┼────────────┘
                              ▼
                    Function Summaries
                              │
                              ▼
                         Taint Engine
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
              Sources     Sanitizers      Sinks
                 └────────────┼────────────┘
                              ▼
                           Findings
                              │
                              ▼
                     Proof / Refutation
                              │
                  ┌───────────┼───────────┐
                  ▼           ▼           ▼
            Vulnerability   Hotspot     Refuted
                  │           │
                  └──────┬────┘
                         ▼
                  CLI / JSON / SARIF
```

This view is intentionally simplified. In practice, the engine must operate as an **analysis dependency graph**.

---

# 3. Layered Architecture

## 3.1 Frontend

Responsibilities:

- discovering Python files;
- parsing;
- preserving source locations;
- collecting syntax errors;
- supporting incremental analysis in the future.

Pipeline:

```text
Python source
    ↓
ast (standard library)
    ↓
PyHIR, through build_hir
```

The parser must not be exposed directly to advanced analyses.

Syntactic plugins may use PyHIR when appropriate, but semantic plugins must depend on PyHIR or PyIR.

> **Decision (2026-09-04): the frontend is the standard-library `ast` module, not Tree-sitter.**
> The document was written with Tree-sitter as the parser. The engine was built behind the
> `build_hir` seam this section requires, with the `ast` module as the only parser, and the
> architecture tests enforce that no layer above the frontend touches a parser object. Every
> later phase was delivered against that frontend. Tree-sitter would add a native dependency,
> a second adapter to keep identical to the first, and incremental parsing whose benefit the
> engine already gets elsewhere: the persistent cache (§11) is keyed per module, so an edit
> re-analyses that module and its importers only, and the whole test suite runs in about two
> seconds. Tree-sitter is therefore retired from the roadmap. The seam stays: a Tree-sitter
> adapter producing the same PyHIR remains possible if error recovery on broken files or
> sub-second editor feedback ever becomes a requirement.

---

## 3.2 PyHIR

PyHIR is a high-level representation independent of the parser.

Example:

```python
cmd = request.args["cmd"]
```

can become:

```text
Assign
 ├── target: Name("cmd")
 └── value:
      GetItem
       ├── GetAttr(Name("request"), "args")
       └── Constant("cmd")
```

Main instructions or nodes:

```text
Module
Function
Class
Assign
AugAssign
Name
Constant
Call
Attribute
Subscript
If
While
For
Return
Import
ImportFrom
BinaryOp
UnaryOp
Compare
Await
Yield
Raise
With
Try
Lambda
Comprehension
```

Objective:

> Decouple the parser from all subsequent analyses.

---

# 4. Semantic Analysis

Starting from PyHIR, the engine builds several analyses.

```text
                     PyHIR
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
      Scopes         Imports       Symbols
```

## 4.1 ScopeAnalysis

Responsibilities:

- local variables;
- global variables;
- `nonlocal` declarations;
- parameters;
- closures;
- function scopes;
- class scopes;
- comprehension scopes.

Example:

```python
x = 1

def foo():
    x = 2
    return x
```

The engine must distinguish between the two `x` symbols.

---

## 4.2 ImportAnalysis

Example:

```python
import os as operating_system
from subprocess import run as execute
```

Result:

```text
operating_system -> python.os
execute          -> python.subprocess.run
```

---

## 4.3 SymbolAnalysis

The engine should prefer canonical identifiers.

Examples:

```text
python.builtins.eval
python.builtins.exec
python.os.system
python.subprocess.run
python.requests.get
flask.request.args
django.http.HttpRequest.GET
```

This ensures that security rules do not depend on the textual name visible in the file.

---

# 5. CFG

Each function is transformed into a Control Flow Graph.

```text
Function
   │
   ▼
Entry
   │
   ▼
BasicBlock
   │
   ├── instructions
   └── terminator
```

Terminators:

```text
Branch
Jump
Return
Raise
Switch-like constructs if needed
```

The CFG must support the computation of:

- predecessors;
- successors;
- dominance;
- post-dominance;
- reachability;
- loops;
- back edges;
- exception edges;
- control dependence.

Example:

```python
if safe:
    x = sanitize(x)

sink(x)
```

becomes approximately:

```text
entry:
    branch %safe, bb_safe, bb_merge

bb_safe:
    ...
    jump bb_merge

bb_merge:
    ...
    call sink(...)
```

---

# 6. PyIR

PyIR is the low-level analysis IR, but it must remain semantically faithful to Python.

Example instructions:

```text
Const
Copy
LoadSymbol
StoreSymbol
GetAttr
SetAttr
GetItem
SetItem
Call
CallMethod
BinaryOp
UnaryOp
Compare
BuildList
BuildTuple
BuildDict
Branch
Jump
Return
Phi
Import
Await
Yield
Raise
WithEnter
WithExit
```

Avoid artificially reproducing LLVM's memory model.

Example:

```python
obj.foo
```

must remain:

```text
%1 = get_attr %obj, "foo"
```

and must not be transformed into the Python equivalent of a `getelementptr`.

---

# 7. SSA

Local values are converted to Static Single Assignment form.

Example:

```python
x = a

if cond:
    x = b

use(x)
```

becomes:

```text
%x.0 = %a

branch %cond, bb_then, bb_merge

bb_then:
    %x.1 = %b
    jump bb_merge

bb_merge:
    %x.2 = phi [%x.0, entry],
               [%x.1, bb_then]

call use(%x.2)
```

Benefits:

- explicit def-use chains;
- constant propagation;
- taint propagation;
- abstract value analysis;
- straightforward handling of merges;
- dependency analysis between values.

---

# 8. Analysis Manager

The core of the system must be an `AnalysisManager`.

Responsibilities:

- registering available analyses;
- registering their dependencies;
- computing them only when needed;
- caching their results;
- invalidating results after transformations;
- exposing a uniform API to plugins.

Conceptual example:

```python
symbols = ctx.get(SymbolAnalysis)
cfg = ctx.get(CFGAnalysis, function)
taint = ctx.get(TaintAnalysis, function)
```

The plugin must not need to know how these results are built.

---

# 9. Analysis DAG

The actual pipeline is a graph.

```text
                     Parse
                       │
                       ▼
                      HIR
              ┌────────┼────────┐
              ▼        ▼        ▼
           Scopes   Imports   Symbols
              │        │        │
              └────────┼────────┘
                       ▼
                      CFG
                       │
                       ▼
                     PyIR
               ┌───────┼─────────┐
               ▼       ▼         ▼
           Dominators DataFlow AbstractValue
                       │
                       ▼
                   CallGraph
                       │
                       ▼
                   Summaries
                       │
                       ▼
                     Taint
```

Dependencies must be declarative.

Example:

```text
TaintAnalysis requires:
    PyIR
    CFG
    SymbolAnalysis
    CallGraph
    FunctionSummaryAnalysis
```

---

# 10. Lazy Evaluation

The engine must not compute every analysis by default.

Example:

```text
Plugin A -> PyHIR (syntax)
Plugin B -> PyHIR
Plugin C -> Symbols
Plugin D -> Taint
```

The engine computes only what is required.

An analysis may also be computed at function granularity.

Example:

```text
ctx.get(CFGAnalysis, foo)
```

must not necessarily force construction of the CFGs for all 10,000 functions in the project.

---

# 11. Cache

Every analysis result must be cacheable.

Possible keys:

```text
AnalysisType
+
ModuleId / FunctionId
+
IR fingerprint
+
Analysis version
+
Plugin/API version
```

Example:

```text
(FunctionId, CFGAnalysis, IRHash)
    ↓
CFGResult
```

A persistent cache can later enable incremental analysis.

---

# 12. Invalidation

Read-only analyses do not modify the IR.

Transformations may invalidate other analyses.

Two families:

```text
AnalysisPass
TransformationPass
```

Example:

```text
SimplifyCFGPass
```

may preserve:

```text
Symbols
Imports
Scopes
```

but invalidate:

```text
Dominators
DataFlow
SSA
Taint
AbstractValue
```

The engine must manage this invalidation automatically.

---

# 13. Plugin API

Avoid:

```python
plugin.on_stage("cfg", arbitrary_object)
```

Prefer typed interfaces.

Example:

```python
class SecurityPlugin:
    requires = {
        SymbolAnalysis,
        TaintAnalysis,
    }

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        ...
```

Other plugin types:

```text
FrontendPlugin
HIRPlugin
IRPlugin
AnalysisProvider
FrameworkModelPlugin
SecurityDetector
RefutationPlugin
ReporterPlugin
DependencyPlugin
SecretPlugin
ConfigPlugin
```

---

# 14. Plugin Manifests

Example:

```yaml
name: sql-injection
version: 1.0.0
plugin_api: 1

requires:
  - semantic.symbols
  - analysis.taint

provides:
  - vulnerability.sql-injection

entrypoint:
  module: plugins.sql_injection
  class: SQLInjectionPlugin
```

Flask plugin:

```yaml
name: flask-model
version: 1.0.0
plugin_api: 1

requires:
  - semantic.symbols

provides:
  - model.http-sources
  - model.flask-routes
```

---

# 15. Analysis Providers and Detectors

This distinction is important.

## Analysis Provider

Produces facts.

Example:

```text
FlaskPlugin
    ↓
route(handler)
request.args -> HTTP_SOURCE
```

The Flask plugin does not need to know about SQL injection.

---

## Detector

Consumes generic facts.

Example:

```text
HTTP_SOURCE
    ↓
Taint Engine
    ↓
SQL_SINK
    ↓
SQLInjectionDetector
```

This avoids:

```text
FlaskSQLInjection
DjangoSQLInjection
FastAPISQLInjection
```

in favor of:

```text
FlaskModel
DjangoModel
FastAPIModel
      ↓
Common Security Model
      ↓
SQLInjectionDetector
```

---

# 16. Security Model Registry

All plugins must be able to register models.

Example:

```text
SourceModel
SinkModel
SanitizerModel
PropagatorModel
FrameworkModel
```

Example:

```text
flask.request.args
    -> Source(HTTP_INPUT)

python.os.system
    -> Sink(COMMAND)

html.escape
    -> Sanitizer(HTML)
```

---

# 17. Global Taint Engine

The taint engine must be shared by all plugins.

Avoid:

```text
SQL plugin      -> own taint engine
Command plugin  -> own taint engine
XSS plugin      -> own taint engine
```

Prefer:

```text
               Global Taint Engine
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
         SQL        COMMAND        HTML
```

Taint kinds can be represented using a bitset:

```text
SQL      = bit 0
COMMAND  = bit 1
HTML     = bit 2
PATH     = bit 3
SSRF     = bit 4
...
```

The join operation generally becomes:

```text
OUT = A | B
```

Plugins register their models and consume the same taint result.

---

# 18. Abstract Value Engine

An SSA value may have an abstract state:

```text
AbstractValue {
    types
    constants
    taints
    numeric_range
    string_constraints
    truthiness
    nullability
}
```

Example:

```text
%x:
    type = str
    taint = HTTP_INPUT
    string_constraint = numeric_only
```

This supports:

- constant propagation;
- type approximation;
- guard validation;
- proof/refutation;
- finding prioritization.

---

# 19. Function Summaries

Interprocedural analyses must use summaries.

Example:

```python
def identity(x):
    return x
```

Summary:

```text
RETURN depends_on PARAM[0]
```

Example:

```python
def execute(cmd):
    os.system(cmd)
```

Summary:

```text
PARAM[0] -> COMMAND_SINK
```

Possible structure:

```text
FunctionSummary {
    return_dependencies
    return_taints
    parameter_sinks
    sanitizers
    mutations
    side_effects
    calls
}
```

---

# 20. Call Graph

The call graph is built from:

- resolved symbols;
- imports;
- direct calls;
- type inference;
- framework models;
- potentially an approximate resolution of dynamic dispatch.

```text
A
├── B
└── C
    └── D
```

Because Python is dynamic, the call graph must support:

```text
KnownTarget
PossibleTargets
UnknownTarget
```

---

# 21. Multi-File Analysis

The engine builds:

```text
ModuleGraph
+
CallGraph
+
FunctionSummaryIndex
```

Example:

```text
routes.py
   ↓
services.py
   ↓
repository.py
   ↓
database.py
```

Summaries must enable whole-project analysis without retaining all PyIR in memory.

---

# 22. Heap and Aliasing

SSA is not sufficient for:

```python
a = []
b = a
b.append(user_input)
sink(a[0])
```

Gradually introduce:

```text
AllocationSite
AbstractObject
HeapLocation
AliasSet
```

Example:

```text
List@foo.py:42.elements
    -> HTTP_INPUT
```

The engine can start with a coarse abstraction and refine it later.

---

# 23. Findings

A finding must reference lightweight IDs.

Example:

```text
Finding {
    rule_id
    severity
    confidence
    function_id
    source_instruction_id
    sink_instruction_id
    message
    metadata
}
```

Avoid storing a complete copy of the CFG or taint path.

The path can be reconstructed during reporting.

---

# 24. Proof / Refutation Engine

After initial detection:

```text
Potential Finding
       ↓
Proof / Refutation
```

Sources of evidence:

```text
Dominators
Post-dominators
Range analysis
String constraints
Type constraints
Path constraints
Sanitizers
Constant propagation
Authorization guards
```

Example:

```python
value = request.args["id"]

if not value.isdigit():
    return

sink(value)
```

The engine can determine that, along the path to the sink:

```text
value = numeric_only
```

The final result may become:

```text
Vulnerability
Hotspot
Refuted
```

---

# 25. Plugin Types

Possible organization:

```text
plugins/
├── syntax/
│   ├── dangerous_eval/
│   └── weak_crypto/
│
├── frameworks/
│   ├── flask/
│   ├── django/
│   └── fastapi/
│
├── security/
│   ├── sql_injection/
│   ├── command_injection/
│   ├── path_traversal/
│   ├── ssrf/
│   └── xss/
│
├── dependency/
│   ├── osv/
│   ├── lockfiles/
│   └── reachability/
│
├── secrets/
│   ├── generic_entropy/
│   └── providers/
│
├── proof/
│   ├── sanitizer/
│   ├── ranges/
│   └── path_constraints/
│
└── reporters/
    ├── cli/
    ├── json/
    └── sarif/
```

---

# 26. Dependency Plugins

The plugin system must not be limited to the PyIR pipeline.

Example:

```text
requirements.txt
pyproject.toml
poetry.lock
uv.lock
       │
       ▼
Dependency Resolver
       │
       ▼
Dependency Graph
       │
       ├── OSV Plugin
       ├── GHSA Plugin
       ├── Policy Plugin
       └── Reachability Plugin
```

The Reachability Plugin can then depend on the Python engine's call graph.

Example:

```text
Vulnerable Package
        +
Affected API
        +
CallGraph
        ↓
Reachable vulnerability
```

---

# 27. Correlation Engine

A global engine must be able to correlate multiple results.

Example:

```text
SCA:
    vulnerable dependency

SAST:
    affected API imported

CallGraph:
    vulnerable function reachable

Taint:
    attacker-controlled value reaches call

        ↓

High-confidence exploitable finding
```

This is a major differentiator.

---

# 28. Reporter API

Reporters consume only normalized findings.

```text
Findings
   │
   ├── CLIReporter
   ├── JSONReporter
   ├── SARIFReporter
   └── future UI/API
```

A reporter must not run an analysis itself.

---

# 29. Performance Model

Let:

```text
N = program size
B = number of basic blocks
E = number of CFG edges
V = number of SSA values
C = number of call graph edges
P = number of plugins
```

The expected cost should be:

```text
Ttotal =
    Tcore
  + Tunique_analyses
  + Σ Tplugin_i
```

and not:

```text
Ttotal =
    P × Tcore
```

Shared analyses must be computed only once.

---

# 30. Memory Complexity

The target model is:

```text
Mtotal =
    Mshared_IR
  + Mshared_analysis_results
  + Σ Mplugin_state
```

and not:

```text
Mtotal =
    P × Mproject
```

Whenever possible, plugins should retain only:

```text
FunctionId
BlockId
InstructionId
ValueId
SymbolId
FindingId
```

---

# 31. Example with 30 Plugins

Suppose:

```text
30 plugins
├── 8 syntax checks
├── 5 framework models
├── 10 security detectors
├── 3 proof plugins
├── 2 dependency plugins
└── 2 reporters
```

The engine must perform the following only once:

```text
Parsing
PyHIR
Symbol resolution
CFG
SSA
CallGraph
Taint
AbstractValue
```

All 30 plugins share these results.

---

# 32. Stable API

Plugins must not access internal classes directly.

Avoid:

```python
engine._cfg_map
engine._symbol_table
engine._ir_storage
```

Prefer:

```python
ctx.functions()
ctx.cfg(function_id)
ctx.symbol(value_id)
ctx.calls(function_id)
ctx.taint(value_id)
ctx.abstract_value(value_id)
ctx.source_location(instruction_id)
```

This API constitutes the Plugin API contract.

---

# 33. Versioning

Plan for the following from the outset:

```text
Plugin API v1
PyHIR schema version
PyIR schema version
Summary schema version
Finding schema version
```

A plugin manifest must be able to declare compatibility:

```yaml
plugin_api: ">=1,<2"
```

---

# 34. Plugin Isolation

Several levels may eventually be supported.

## In-Process

Fast and simple.

```text
Core Engine
   ↓
Python plugin module
```

Advantages:

- low overhead;
- direct access to APIs;
- easy development.

Disadvantage:

- a plugin can crash the engine.

## Out-of-Process

Possible for untrusted plugins.

```text
Core
 ↓
RPC / IPC
 ↓
Plugin Process
```

Safer but more expensive.

The engine can begin with in-process plugins while providing an abstraction compatible with future isolation.

---

# 35. Example of Resolving a Plugin's Dependencies

Plugin:

```text
SQLInjectionPlugin
```

Declares:

```text
requires:
    TaintAnalysis
    SymbolAnalysis
```

The engine resolves:

```text
SQLInjectionPlugin
        │
        ├──── TaintAnalysis
        │        │
        │        ├── PyIR
        │        ├── CFG
        │        ├── Symbols
        │        └── Summaries
        │
        └──── SymbolAnalysis
                 │
                 ├── PyHIR
                 ├── Imports
                 └── Scopes
```

The actual DAG becomes:

```text
Parse
  ↓
PyHIR
  ↓
Scopes + Imports
  ↓
Symbols
  ↓
CFG
  ↓
PyIR
  ↓
Summaries
  ↓
Taint
  ↓
SQLInjectionPlugin
```

---

# 36. Example of Plugin Composition

```text
FlaskModelPlugin
    ↓
register HTTP sources

SQLAlchemyModelPlugin
    ↓
register SQL sinks

Taint Engine
    ↓
connect source → sink

SQLInjectionPlugin
    ↓
Finding

PathConstraintRefuter
    ↓
Finding validated/refuted

SARIFReporter
```

Each component remains independent.

---

# 37. Proposed Repository Structure

```text
engine/
├── frontend/
│   ├── parser/
│   └── source_manager/
│
├── hir/
│   ├── nodes/
│   ├── builder/
│   └── visitors/
│
├── semantic/
│   ├── scopes/
│   ├── imports/
│   └── symbols/
│
├── cfg/
│   ├── graph/
│   ├── builder/
│   └── dominance/
│
├── ir/
│   ├── values/
│   ├── instructions/
│   ├── blocks/
│   ├── functions/
│   └── ssa/
│
├── analysis/
│   ├── manager/
│   ├── registry/
│   ├── dependencies/
│   ├── cache/
│   └── invalidation/
│
├── dataflow/
│   ├── lattice/
│   ├── worklist/
│   └── solver/
│
├── abstract/
│   ├── values/
│   ├── ranges/
│   ├── strings/
│   └── types/
│
├── interprocedural/
│   ├── callgraph/
│   ├── summaries/
│   └── modulegraph/
│
├── taint/
│   ├── engine/
│   ├── models/
│   ├── sources/
│   ├── sinks/
│   └── sanitizers/
│
├── findings/
│   ├── model/
│   ├── correlation/
│   └── refutation/
│
├── plugins/
│   ├── api/
│   ├── loader/
│   ├── manifest/
│   └── registry/
│
├── reporters/
│   ├── cli/
│   ├── json/
│   └── sarif/
│
└── tests/
    ├── unit/
    ├── integration/
    ├── fixtures/
    └── plugins/
```

---

# 38. Recommended Development Order

## Phase 1 — Infrastructure

```text
SourceManager
Frontend (ast adapter; Tree-sitter retired, see §3.1)
PyHIR
Plugin API
Plugin Loader
Analysis Manager
```

## Phase 2 — Semantics

```text
Scopes
Imports
Symbols
Canonical Symbol IDs
```

## Phase 3 — IR

```text
CFG
PyIR
SSA
Def-use
Dominators
```

## Phase 4 — Data Flow

```text
Worklist solver
Lattice API
AbstractValue
Constant propagation
```

## Phase 5 — Security Core

```text
Source/Sink/Sanitizer Registry
Global Taint Engine
Basic detectors
```

## Phase 6 — Interprocedural Analysis

```text
CallGraph
FunctionSummary
ModuleGraph
Fixpoint
```

## Phase 7 — Frameworks

```text
Flask
Django
FastAPI
SQLAlchemy
Requests/httpx
```

## Phase 8 — False-Positive Reduction

```text
Ranges
Path constraints
Dominant guards
Proof/refutation
```

## Phase 9 — Ecosystem

```text
SCA
Secrets
Dependency reachability
Correlation
SBOM
```

## Phase 10 — Performance

```text
Persistent cache
Incremental parsing (covered by the per-module cache; Tree-sitter retired, see §3.1)
Incremental summaries
Parallel analysis
Memory eviction
```

---

# 39. Architectural Rules to Preserve

### Rule 1

> A plugin requests an analysis; it does not recompute it.

### Rule 2

> Analysis results are shared and cached.

### Rule 3

> IRs are immutable for standard analyses.

### Rule 4

> Transformations explicitly declare what they invalidate.

### Rule 5

> Frameworks enrich the model; detectors detect vulnerabilities.

### Rule 6

> The taint engine is global and supports multiple taint kinds.

### Rule 7

> Interprocedural results use Function Summaries.

### Rule 8

> Plugins depend on a stable API, never on internal structures.

### Rule 9

> Analyses are lazy and, whenever possible, granular at the function level.

### Rule 10

> Findings use lightweight identifiers instead of graph copies.

---

# 40. Target Architecture

```text
                           ┌──────────────────────┐
                           │    Plugin Manager    │
                           │ discovery / manifest │
                           │ versions / loading   │
                           └──────────┬───────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │   Analysis Manager   │
                           │                      │
                           │ dependency DAG       │
                           │ lazy evaluation      │
                           │ caching              │
                           │ invalidation         │
                           └──────────┬───────────┘
                                      │
          ┌───────────────────────────┼──────────────────────────┐
          │                           │                          │
          ▼                           ▼                          ▼
      Frontend                    Semantic                     PyIR
    ast / PyHIR            Scopes / Imports / Symbols      CFG / SSA
          │                           │                          │
          └───────────────────────────┼──────────────────────────┘
                                      ▼
                            Generic Analyses
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
                DataFlow         CallGraph        AbstractValue
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      ▼
                             Function Summaries
                                      │
                                      ▼
                                Taint Engine
                                      │
               ┌──────────────────────┼──────────────────────┐
               ▼                      ▼                      ▼
          Framework Models         Detectors              Proofs
               │                      │                      │
               └──────────────────────┼──────────────────────┘
                                      ▼
                                   Findings
                                      │
                                      ▼
                              Correlation Engine
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                  Vulnerability    Hotspot      Refuted
                         │            │
                         └──────┬─────┘
                                ▼
                        CLI / JSON / SARIF
```

---

# 41. Final Vision

The project must not be designed solely as a Python vulnerability scanner.

It must be designed as:

> **A programmable and extensible Python static analysis framework that provides a frontend, an HIR, an SSA IR, shared program analyses, and a plugin API for building specialized detectors.**

Security then becomes a collection of plugins built on top of this engine.

This separation eventually allows the framework to host:

```text
Security
Bug Detection
Code Quality
Performance
Compliance
Framework-specific analysis
Dependency Analysis
Supply-chain analysis
Custom enterprise policies
Research analyses
```

without duplicating the fundamental infrastructure.
