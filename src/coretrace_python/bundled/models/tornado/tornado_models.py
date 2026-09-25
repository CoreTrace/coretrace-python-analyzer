"""Tornado security models: ``RequestHandler`` subclasses are entry points whose inherited
request methods are HTTP sources and whose ``write``, ``finish`` and ``redirect`` are
sinks; the HTTP clients are SSRF sinks with untrusted responses."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TEXT_KINDS, EntryPoint, Model, Sanitizer, Sink, Source, TaintKind

_HANDLERS = ("tornado.web.RequestHandler", "tornado.websocket.WebSocketHandler")
# Text, which cannot hold a query operator; the request object holds the raw body too.
_TEXT_METHODS = (
    "get_argument", "get_arguments", "get_query_argument", "get_query_arguments",
    "get_body_argument", "get_body_arguments", "get_cookie", "path_args", "path_kwargs",
)
_CLIENTS = ("tornado.httpclient.AsyncHTTPClient.fetch", "tornado.httpclient.HTTPClient.fetch")
_TARGET_ONLY = ((TaintKind.REDIRECT, (0,)),)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class TornadoModels(ModelPlugin):
    name: ClassVar[str] = "tornado-models"
    models: ClassVar[tuple[Model, ...]] = (
        # A request handler's parameters are segments of its URL; a WebSocket handler also
        # receives the messages, raw payloads a ``json.loads`` may decode.
        EntryPoint(_sym("tornado.web.RequestHandler"), "http", TEXT_KINDS),
        EntryPoint(_sym("tornado.websocket.WebSocketHandler"), "http"),
        *(Source(_sym(f"{handler}.{method}"), "http", TEXT_KINDS) for handler in _HANDLERS for method in _TEXT_METHODS),
        *(Source(_sym(f"{handler}.request"), "http") for handler in _HANDLERS),
        *(Sink(_sym(f"{handler}.write"), TaintKind.HTML) for handler in _HANDLERS),
        *(Sink(_sym(f"{handler}.finish"), TaintKind.HTML) for handler in _HANDLERS),
        *(Sink(_sym(f"{handler}.redirect"), TaintKind.REDIRECT, _TARGET_ONLY) for handler in _HANDLERS),
        *(Sink(_sym(client), TaintKind.SSRF) for client in _CLIENTS),
        *(Source(_sym(client), "http-response") for client in _CLIENTS),
        Sanitizer(_sym("tornado.escape.xhtml_escape"), TaintKind.HTML),
    )
