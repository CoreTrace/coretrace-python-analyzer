"""Registry of loaded plugins, indexed by name and by provided capability."""

from __future__ import annotations

from collections.abc import Iterator

from coretrace_python.plugins.loader import LoadedPlugin
from coretrace_python.plugins.manifest import ManifestError


class PluginRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, LoadedPlugin] = {}
        self._by_capability: dict[str, list[LoadedPlugin]] = {}

    def add(self, loaded: LoadedPlugin) -> None:
        name = loaded.manifest.name
        if name in self._by_name:
            raise ManifestError(f"plugin {name!r} is already registered")
        self._by_name[name] = loaded
        for capability in loaded.manifest.provides:
            self._by_capability.setdefault(capability, []).append(loaded)

    def plugin(self, name: str) -> LoadedPlugin:
        return self._by_name[name]

    def providers(self, capability: str) -> tuple[LoadedPlugin, ...]:
        return tuple(self._by_capability.get(capability, ()))

    def __iter__(self) -> Iterator[LoadedPlugin]:
        return iter(self._by_name.values())

    def __len__(self) -> int:
        return len(self._by_name)
