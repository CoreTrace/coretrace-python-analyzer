"""Plugin API, manifests, loader and registry (architecture §13, §14, §32–§34)."""

from coretrace_python.plugins.api import (
    PLUGIN_API_VERSION,
    ModelPlugin,
    Plugin,
    PluginContext,
    ProjectContext,
    ProjectPlugin,
    run_plugins,
)
from coretrace_python.plugins.detectors import SymbolCallDetector, TaintDetector
from coretrace_python.plugins.loader import (
    IncompatiblePluginError,
    LoadedPlugin,
    discover_plugins,
    load_plugin,
)
from coretrace_python.plugins.manifest import (
    Entrypoint,
    ManifestError,
    PluginManifest,
    VersionRange,
    load_manifest,
)
from coretrace_python.plugins.registry import PluginRegistry

__all__ = [
    "PLUGIN_API_VERSION",
    "Entrypoint",
    "IncompatiblePluginError",
    "LoadedPlugin",
    "ManifestError",
    "ModelPlugin",
    "Plugin",
    "PluginContext",
    "PluginManifest",
    "PluginRegistry",
    "ProjectContext",
    "ProjectPlugin",
    "SymbolCallDetector",
    "TaintDetector",
    "VersionRange",
    "discover_plugins",
    "load_manifest",
    "load_plugin",
    "run_plugins",
]
