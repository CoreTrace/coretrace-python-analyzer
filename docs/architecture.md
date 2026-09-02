# CoreTrace Python Analysis Engine Architecture

## Product direction

CoreTrace Python Analyzer is evolving from a security-specific source scanner into an
extensible static-analysis engine. Security detectors will be plugins built on shared,
language-level analysis infrastructure.

The target data path is:

```text
Python project
    -> source discovery and SourceManager
    -> parser (Tree-sitter target; stdlib ast adapter initially)
    -> parser-independent PyHIR
    -> scopes, imports, and canonical symbols
    -> control-flow graph
    -> SSA PyIR
    -> shared analysis DAG
    -> models, detectors, and proof/refutation plugins
    -> normalized findings
    -> CLI, JSON, and SARIF reporters
```

## Architectural boundaries

1. Source text and locations belong to `source`; all later representations reference stable
   source IDs and spans.
2. Parser-specific objects stop at `frontend`. Semantic analysis and lowering consume PyHIR,
   never `ast.*` or Tree-sitter nodes.
3. `semantic` owns scopes, imports, and symbols. PyIR lowering consumes semantic results rather
   than resolving names itself.
4. CFG is built before SSA. SSA construction is a transformation over non-SSA control flow.
5. Analyses are immutable providers managed through a dependency DAG. Results are lazy, cached,
   and invalidated explicitly after transformations.
6. Plugins consume versioned, typed result APIs. They do not access engine internals or rebuild
   shared analyses.
7. Framework plugins provide models and facts; detectors consume generic facts. The taint engine
   is global and multi-kind.
8. Findings store lightweight IDs. Reporters consume normalized findings and never initiate
   analysis.

## Migration strategy

The migration is incremental so every merged branch leaves the CLI usable.

### Phase 1: frontend foundation

- Introduce `SourceManager`, `SourceId`, and `SourceSpan`.
- Introduce parser-independent PyHIR.
- Adapt Python's standard-library AST into PyHIR.
- Route existing PyIR lowering through PyHIR without changing emitted output.

Tree-sitter is intentionally behind the parser boundary. It can replace the initial AST adapter
once PyHIR is stable, without affecting semantic analysis or PyIR.

### Phase 2: semantic layer

- Move import binding and canonical symbol resolution into `semantic`.
- Add lexical scopes, local/global/nonlocal classification, closures, and class scopes.
- Publish immutable semantic results keyed by stable IDs.

### Phase 3: control flow and SSA

- Build per-function CFGs with explicit terminators and graph integrity checks.
- Add dominators and dominance frontiers.
- Transform local reads and writes into SSA with phi nodes and def-use chains.

### Phase 4: shared analysis infrastructure

- Add typed analysis providers and dependency declarations.
- Add lazy evaluation, caching, and transformation invalidation.
- Validate the framework with constant propagation and abstract values.

### Later phases

- Plugin manifests, registry, and versioned API.
- Global multi-kind taint and security model registry.
- Call graph, function summaries, module graph, and interprocedural fixpoints.
- Framework models, detectors, proof/refutation, correlation, and reporters.
- Persistent caching, incremental parsing, parallelism, and memory eviction.

## Current milestone acceptance criteria

The frontend-foundation milestone is complete when:

- the CLI loads files through `SourceManager`;
- source locations use `SourceSpan` with stable `SourceId` values;
- supported Python syntax is represented in PyHIR;
- PyIR lowering no longer imports or accepts `ast` nodes;
- existing `--emit-ir` output remains deterministic;
- existing tests pass alongside focused source and PyHIR tests.

