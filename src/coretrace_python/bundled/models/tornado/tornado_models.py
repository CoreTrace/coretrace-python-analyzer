"""Tornado security models: ``RequestHandler`` subclasses are entry points whose inherited
request methods are HTTP sources and whose ``write``, ``finish`` and ``redirect`` are
sinks; the HTTP clients are SSRF sinks with untrusted responses."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import EntryPoint, Model, Sanitizer, Sink, Source, TaintKind

_HANDLERS = ("tornado.web.RequestHandler", "tornado.websocket.WebSocketHandler")
_REQUEST_METHODS = (
    "get_argument", "get_arguments", "get_query_argument", "get_query_arguments",
    "get_body_argument", "get_body_arguments", "get_cookie", "request", "path_args", "path_kwargs",
)
_CLIENTS = ("tornado.httpclient.AsyncHTTPClient.fetch", "tornado.httpclient.HTTPClient.fetch")
_TARGET_ONLY = ((TaintKind.REDIRECT, (0,)),)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class TornadoModels(ModelPlugin):
    name: ClassVar[str] = "tornado-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(EntryPoint(_sym(handler), "http") for handler in _HANDLERS),
        *(Source(_sym(f"{handler}.{method}"), "http") for handler in _HANDLERS for method in _REQUEST_METHODS),
        *(Sink(_sym(f"{handler}.write"), TaintKind.HTML) for handler in _HANDLERS),
        *(Sink(_sym(f"{handler}.finish"), TaintKind.HTML) for handler in _HANDLERS),
        *(Sink(_sym(f"{handler}.redirect"), TaintKind.REDIRECT, _TARGET_ONLY) for handler in _HANDLERS),
        *(Sink(_sym(client), TaintKind.SSRF) for client in _CLIENTS),
        *(Source(_sym(client), "http-response") for client in _CLIENTS),
        Sanitizer(_sym("tornado.escape.xhtml_escape"), TaintKind.HTML),
    )
