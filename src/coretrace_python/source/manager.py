"""Ownership and loading of source files."""

from __future__ import annotations

from pathlib import Path

from coretrace_python.source.model import SourceFile, SourceId


def module_name_for(path: Path) -> str:
    """Dotted module name of ``path``, walking up through ``__init__.py`` packages."""

    parts = [path.stem]
    directory = path.parent
    while (directory / "__init__.py").is_file():
        parts.append(directory.name)
        directory = directory.parent
    return ".".join(reversed(parts))


class SourceManager:
    """Own source text and return one canonical object for each source ID."""

    def __init__(self) -> None:
        self._sources: dict[SourceId, SourceFile] = {}

    def add_source(self, name: str, text: str, module_name: str | None = None) -> SourceFile:
        source_id = SourceId(name)
        existing = self._sources.get(source_id)
        if existing is not None:
            if existing.text != text:
                raise ValueError(f"source {name!r} already exists with different text")
            return existing

        source = SourceFile(
            source_id=source_id,
            text=text,
            module_name=module_name if module_name is not None else Path(name).stem,
        )
        self._sources[source_id] = source
        return source

    def load_file(self, path: str | Path) -> SourceFile:
        resolved_path = Path(path).resolve()
        source_id = SourceId(str(resolved_path))
        existing = self._sources.get(source_id)
        if existing is not None:
            return existing

        # utf-8-sig accepts ordinary UTF-8 and strips a leading UTF-8 BOM.
        text = resolved_path.read_text(encoding="utf-8-sig")
        source = SourceFile(
            source_id=source_id,
            text=text,
            module_name=module_name_for(resolved_path),
            path=resolved_path,
        )
        self._sources[source_id] = source
        return source

    def get(self, source_id: SourceId) -> SourceFile:
        try:
            return self._sources[source_id]
        except KeyError as error:
            raise KeyError(f"unknown source ID: {source_id}") from error

    def __len__(self) -> int:
        return len(self._sources)

