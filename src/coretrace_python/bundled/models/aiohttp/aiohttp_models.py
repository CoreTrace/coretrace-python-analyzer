"""aiohttp security models: handlers receive HTTP input whether they take an annotated
``web.Request``, are registered on the router or decorated by a ``RouteTableDef``;
responses, file responses and redirect exceptions are sinks; client sessions are SSRF
sinks whose responses are untrusted."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import (
    EntryPoint,
    Model,
    RequestObject,
    RouteRegistrar,
    Sink,
    Source,
    TaintKind,
    TypedParameter,
)

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_REQUEST_CLASSES = ("aiohttp.web.Request", "aiohttp.web_request.Request")
_ROUTERS = ("aiohttp.web.Application.router", "aiohttp.web.UrlDispatcher")
# ``@routes.get('/')`` on a ``RouteTableDef``.
_ROUTE_TABLES = tuple(f"aiohttp.web.RouteTableDef.{method}" for method in (*_METHODS, "route", "view"))
# ``app.router.add_route('GET', '/', handler)``, ``app.router.add_get('/', handler)`` and
# ``app.add_routes([web.get('/', handler)])``, each with the argument naming the handler.
_ROUTE_CALLS = (
    *((f"{router}.add_route", 2) for router in _ROUTERS),
    *((f"{router}.add_{method}", 1) for router in _ROUTERS for method in (*_METHODS, "view")),
    ("aiohttp.web.route", 2),
    *((f"aiohttp.web.{method}", 1) for method in (*_METHODS, "view")),
)
# What a request gives as text; its body (``json()``, ``text()``, ``read()``) may hold a
# structure.
_REQUEST_TEXT = (
    "query", "rel_url", "url", "path", "raw_path", "path_qs", "query_string", "match_info", "headers",
    "raw_headers", "cookies", "method", "host", "scheme", "remote", "forwarded", "content_type", "charset",
    "if_modified_since", "post",
)
_REDIRECTS = ("HTTPFound", "HTTPMovedPermanently", "HTTPSeeOther", "HTTPTemporaryRedirect", "HTTPPermanentRedirect")
_CLIENT_FUNCTIONS = (
    *(f"aiohttp.ClientSession.{method}" for method in (*_METHODS, "request")),
    *(f"aiohttp.client.ClientSession.{method}" for method in (*_METHODS, "request")),
    "aiohttp.request",
)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class AiohttpModels(ModelPlugin):
    name: ClassVar[str] = "aiohttp-models"
    models: ClassVar[tuple[Model, ...]] = (
        # The whole request is attacker-controlled: its query, match info, headers,
        # cookies and body all come from the client.
        *(TypedParameter(_sym(cls), "http") for cls in _REQUEST_CLASSES),
        *(EntryPoint(_sym(table), "http") for table in _ROUTE_TABLES),
        *(RouteRegistrar(_sym(call), argument, "http", keyword="handler") for call, argument in _ROUTE_CALLS),
        *(
            RequestObject(_sym(symbol), _REQUEST_TEXT)
            for symbol in (*_REQUEST_CLASSES, *_ROUTE_TABLES, *(call for call, _ in _ROUTE_CALLS))
        ),
        Sink(_sym("aiohttp.web.Response"), TaintKind.HTML),
        Sink(_sym("aiohttp.web.FileResponse"), TaintKind.PATH),
        *(Sink(_sym(f"aiohttp.web.{exception}"), TaintKind.REDIRECT) for exception in _REDIRECTS),
        *(Sink(_sym(f"aiohttp.web_exceptions.{exception}"), TaintKind.REDIRECT) for exception in _REDIRECTS),
        *(Sink(_sym(function), TaintKind.SSRF) for function in _CLIENT_FUNCTIONS),
        *(Source(_sym(function), "http-response") for function in _CLIENT_FUNCTIONS),
    )
