"""Architectural boundary tests derived from ``docs/architecture.md``.

They encode §3.1 (parser objects stop at the frontend), §32 (stable API instead of
internals), §37 (repository structure) and §39 (rules to preserve).

These tests describe the "Align repository layout with the target structure" roadmap
item. They are expected to remain red until HIR-to-PyIR lowering and import binding
leave ``frontend`` and the CLI stops reaching into frontend submodules.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

PACKAGE = "coretrace_python"
PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "src" / PACKAGE

# Only the frontend may touch a concrete parser (§3.1).
PARSER_MODULES = {"ast", "tree_sitter", "tree_sitter_python"}

# Dependency direction of the pipeline (§2, §37). A package may import only packages
# with a strictly lower layer number, or itself. ``analysis`` is infrastructure every
# provider subclasses, so it sits below the analyses it manages (§8).
LAYERS = {
    "source": 0,
    "hir": 1,
    "analysis": 2,
    "frontend": 2,
    "semantic": 3,
    "cfg": 4,
    "ir": 5,
    "dataflow": 6,
    "abstract": 7,
    "interprocedural": 7,
    "taint": 8,
    "findings": 9,
    "dependency": 10,
    "plugins": 11,
    "reporters": 12,
}

# Top-level modules that wire the pipeline together and may import any layer.
ROOT_MODULES = {"__init__", "__main__", "cache", "cli", "engine"}


def package_files() -> Iterator[tuple[Path, str, str]]:
    """Yield ``(path, layer, dotted module name)`` for every module in the package."""

    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        parts = path.relative_to(PACKAGE_ROOT).with_suffix("").parts
        layer = parts[0]
        module = ".".join((PACKAGE, *parts))
        yield path, layer, module


def imported_modules(path: Path, module: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line, absolute module name)`` for every import in ``path``."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    if module.endswith(".__init__"):
        package = module[: -len(".__init__")]
    else:
        package = module.rsplit(".", 1)[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.rsplit(".", node.level - 1)[0] if node.level > 1 else package
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            yield node.lineno, target


def violations() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {
        "parser": [],
        "layers": [],
        "frontend_privacy": [],
        "undeclared": [],
    }
    for path, layer, module in package_files():
        location = path.relative_to(PACKAGE_ROOT.parent)
        is_root_module = layer in ROOT_MODULES
        if not is_root_module and layer not in LAYERS:
            found["undeclared"].append(f"{location}: package {layer!r} is not declared in LAYERS")
            continue
        for line, target in imported_modules(path, module):
            top = target.split(".")[0]
            if top in PARSER_MODULES and layer != "frontend":
                found["parser"].append(f"{location}:{line}: imports parser module {target!r}")
            if top != PACKAGE or "." not in target:
                continue
            target_layer = target.split(".")[1]
            if target.startswith(f"{PACKAGE}.frontend.") and layer != "frontend":
                found["frontend_privacy"].append(
                    f"{location}:{line}: imports frontend submodule {target!r};"
                    f" only `{PACKAGE}.frontend` is public"
                )
            if is_root_module or target_layer == layer:
                continue
            if target_layer not in LAYERS:
                found["undeclared"].append(
                    f"{location}:{line}: imports undeclared layer {target_layer!r}"
                )
            elif LAYERS[target_layer] >= LAYERS[layer]:
                found["layers"].append(
                    f"{location}:{line}: {layer!r} (layer {LAYERS[layer]}) must not import"
                    f" {target_layer!r} (layer {LAYERS[target_layer]})"
                )
    return found


def test_every_package_declares_its_layer() -> None:
    assert violations()["undeclared"] == []


def test_only_the_frontend_imports_a_concrete_parser() -> None:
    assert violations()["parser"] == []


def test_dependencies_follow_the_pipeline_direction() -> None:
    assert violations()["layers"] == []


def test_frontend_submodules_are_private() -> None:
    assert violations()["frontend_privacy"] == []


def test_lowering_no_longer_lives_in_the_frontend() -> None:
    assert not (PACKAGE_ROOT / "frontend" / "lowering.py").exists()
    assert not (PACKAGE_ROOT / "frontend" / "imports.py").exists()
    assert not (PACKAGE_ROOT / "frontend" / "symbols.py").exists()


def test_semantic_package_exists() -> None:
    assert (PACKAGE_ROOT / "semantic" / "__init__.py").exists()
