"""Ownership and loading of source files."""

from __future__ import annotations

import re
from pathlib import Path

from coretrace_python.source.model import ImportName, SourceFile, SourceId


def import_names_for(path: Path, root: Path | None = None) -> tuple[ImportName, ...]:
    """The names the file ``path`` can be imported by, its module name first, each with
    the directory an import of it starts from. A package's ``__init__.py`` is named after
    the package itself.

    The module name follows the packages the file is in, as Python takes a directory
    without ``__init__.py`` inside a regular package for a portion of it (PEP 420): it
    runs from the parent of the outermost directory holding an ``__init__.py``, searched
    up through directories without one as far as ``root``, the project's, and above it
    while each directory holds one (#264). In no package, or without a root, it runs from
    the first directory without an ``__init__.py`` above the file. That second way is how
    a script run from that directory imports the file (``sys.path[0]``): when it gives
    another name, the file has that name too."""

    parts = [] if path.name == "__init__.py" else [path.stem]
    directory = path.parent
    while (directory / "__init__.py").is_file():
        parts.append(directory.name)
        directory = directory.parent
    script = ImportName(".".join(reversed(parts)) or path.stem, directory)
    top = None if root is None else _outermost_package(path.parent, root)
    if top is None or top.parent == script.root:
        return (script,)
    named = path.relative_to(top.parent).with_suffix("").parts
    return (ImportName(".".join(named[:-1] if named[-1] == "__init__" else named), top.parent), script)


def _outermost_package(directory: Path, root: Path) -> Path | None:
    """The outermost directory holding an ``__init__.py`` among ``directory`` and those
    above it up to ``root``, and above ``root`` while each holds one; ``None`` when none
    does, or ``directory`` is not under ``root``."""

    if directory != root and root not in directory.parents:
        return None
    top = None
    while True:
        if (directory / "__init__.py").is_file():
            top = directory
        if directory == root:
            break
        directory = directory.parent
    if top == root:
        while (top.parent / "__init__.py").is_file():
            top = top.parent
    return top


def module_name_for(path: Path, root: Path | None = None) -> str:
    """Dotted module name of ``path`` (``import_names_for``)."""

    return import_names_for(path, root)[0].name


def decode_text(data: bytes) -> str:
    """Decode a text file, honouring a UTF-8 or UTF-16 byte order mark; Windows tools
    such as ``pip freeze`` write UTF-16 with one."""

    for mark, encoding in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(mark):
            return data.decode(encoding)
    return data.decode("utf-8")


# A line break as Python reads one.
LINE_BREAK = re.compile(r"\r\n|\r|\n")


def lines_of(text: str) -> list[str]:
    """The lines of ``text`` as Python counts them: broken by ``\\n``, ``\\r\\n`` or a lone
    ``\\r``, never by U+2028, U+0085, a form feed or the other separators
    ``str.splitlines`` also breaks on. Every line number of the engine counts by it."""

    lines = LINE_BREAK.split(text)
    if lines[-1] == "":
        lines.pop()
    return lines


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

    def load_file(self, path: str | Path, root: Path | None = None) -> SourceFile:
        """The file at ``path``, named as a module of the project under ``root``
        (``import_names_for``); without a root, from the first directory without an
        ``__init__.py`` above it."""

        resolved_path = Path(path).resolve()
        source_id = SourceId(str(resolved_path))
        existing = self._sources.get(source_id)
        if existing is not None:
            return existing

        text = decode_text(resolved_path.read_bytes())
        names = import_names_for(resolved_path, None if root is None else root.resolve())
        source = SourceFile(
            source_id=source_id,
            text=text,
            module_name=names[0].name,
            path=resolved_path,
            is_package=resolved_path.name == "__init__.py",
            import_names=names,
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

