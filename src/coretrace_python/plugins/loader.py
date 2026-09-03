"""In-process plugin loading (architecture §14, §34)."""

from __future__ import annotations

import hashlib
import importlib.util
from dataclasses import dataclass
from pathlib import Path

from coretrace_python.analysis import AnalysisManager
from coretrace_python.plugins.api import PLUGIN_API_VERSION, Plugin
from coretrace_python.plugins.manifest import ManifestError, PluginManifest, load_manifest

MANIFEST_FILENAME = "plugin.toml"


class IncompatiblePluginError(Exception):
    """The plugin targets a plugin API version this engine does not provide."""


@dataclass(frozen=True)
class LoadedPlugin:
    manifest: PluginManifest
    plugin: Plugin
    directory: Path


def load_plugin(directory: Path, manager: AnalysisManager) -> LoadedPlugin:
    """Load the plugin in ``directory`` and check it against its manifest."""

    manifest_path = directory / MANIFEST_FILENAME
    manifest = load_manifest(manifest_path)
    if not manifest.plugin_api.contains(PLUGIN_API_VERSION):
        raise IncompatiblePluginError(
            f"plugin {manifest.name!r} requires plugin_api {manifest.plugin_api}"
            f" but this engine provides {PLUGIN_API_VERSION}"
        )
    for analysis_name in manifest.requires:
        try:
            manager.analysis(analysis_name)
        except KeyError:
            raise ManifestError(
                f"{manifest_path}: unknown analysis {analysis_name!r} in requires"
            ) from None

    plugin_class = _import_entrypoint(directory, manifest)
    declared = {analysis.name for analysis in plugin_class.requires}
    if declared != set(manifest.requires):
        raise ManifestError(
            f"{manifest_path}: manifest requires {sorted(manifest.requires)}"
            f" but {manifest.entrypoint.class_name} declares {sorted(declared)}"
        )
    return LoadedPlugin(manifest, plugin_class(), directory)


def discover_plugins(root: Path, manager: AnalysisManager) -> tuple[LoadedPlugin, ...]:
    """Load every plugin below ``root``, in path order."""

    return tuple(
        load_plugin(manifest_path.parent, manager)
        for manifest_path in sorted(root.rglob(MANIFEST_FILENAME))
    )


def _import_entrypoint(directory: Path, manifest: PluginManifest) -> type[Plugin]:
    module_path = directory / f"{manifest.entrypoint.module}.py"
    if not module_path.is_file():
        raise ManifestError(
            f"{directory / MANIFEST_FILENAME}: entrypoint module"
            f" {manifest.entrypoint.module!r} not found"
        )
    unique = hashlib.sha1(str(module_path.resolve()).encode()).hexdigest()[:12]
    spec = importlib.util.spec_from_file_location(f"coretrace_plugin_{unique}", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    candidate = getattr(module, manifest.entrypoint.class_name, None)
    if not (isinstance(candidate, type) and issubclass(candidate, Plugin)):
        raise ManifestError(
            f"{directory / MANIFEST_FILENAME}: entrypoint class"
            f" {manifest.entrypoint.class_name!r} is not a Plugin"
        )
    return candidate
