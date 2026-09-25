"""Bottle security models: ``@route``, ``@get`` and the methods of a ``Bottle`` application
are entry points, ``bottle.request`` is the HTTP source, ``redirect``, ``static_file``,
``template`` and ``HTTPResponse`` are sinks, ``html_escape`` a sanitizer."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TEXT_KINDS, EntryPoint, Model, Sanitizer, Sink, Source, TaintKind

_METHODS = ("route", "get", "post", "put", "delete", "patch")
# Text, which cannot hold a query operator; JSON, raw bodies and files may hold a structure.
_TEXT_ATTRIBUTES = (
    "query", "forms", "params", "headers", "cookies", "GET", "POST",
    "url", "path", "fullpath", "query_string", "get_cookie", "get_header",
)
_PAYLOAD_ATTRIBUTES = ("json", "body", "files")
_FIRST_ONLY = lambda kind: ((kind, (0,)),)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class BottleModels(ModelPlugin):
    name: ClassVar[str] = "bottle-models"
    models: ClassVar[tuple[Model, ...]] = (
        # A route's parameters are segments of its URL.
        *(EntryPoint(_sym(f"bottle.{method}"), "http", TEXT_KINDS) for method in _METHODS),
        *(EntryPoint(_sym(f"bottle.Bottle.{method}"), "http", TEXT_KINDS) for method in _METHODS),
        *(Source(_sym(f"bottle.request.{attribute}"), "http", TEXT_KINDS) for attribute in _TEXT_ATTRIBUTES),
        *(Source(_sym(f"bottle.request.{attribute}"), "http") for attribute in _PAYLOAD_ATTRIBUTES),
        Sink(_sym("bottle.redirect"), TaintKind.REDIRECT, _FIRST_ONLY(TaintKind.REDIRECT)),
        # ``static_file(filename, root)``: the root is the application's own.
        Sink(_sym("bottle.static_file"), TaintKind.PATH, _FIRST_ONLY(TaintKind.PATH)),
        # ``template(source_or_name, **variables)``: a tainted template is injection, the
        # variables are escaped by the engine.
        Sink(_sym("bottle.template"), TaintKind.HTML, _FIRST_ONLY(TaintKind.HTML)),
        Sink(_sym("bottle.HTTPResponse"), TaintKind.HTML),
        Sanitizer(_sym("bottle.html_escape"), TaintKind.HTML),
    )
