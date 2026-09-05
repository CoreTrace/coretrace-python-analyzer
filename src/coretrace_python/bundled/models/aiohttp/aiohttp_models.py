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
    RouteRegistrar,
    Sink,
    Source,
    TaintKind,
    TypedParameter,
)

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_REQUEST_CLASSES = ("aiohttp.web.Request", "aiohttp.web_request.Request")
_ROUTERS = ("aiohttp.web.Application.router", "aiohttp.web.UrlDispatcher")
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
        # ``@routes.get('/')`` on a ``RouteTableDef``.
        *(EntryPoint(_sym(f"aiohttp.web.RouteTableDef.{method}"), "http") for method in (*_METHODS, "route", "view")),
        # ``app.router.add_route('GET', '/', handler)`` and ``app.router.add_get('/', handler)``.
        *(RouteRegistrar(_sym(f"{router}.add_route"), 2, "http", keyword="handler") for router in _ROUTERS),
        *(
            RouteRegistrar(_sym(f"{router}.add_{method}"), 1, "http", keyword="handler")
            for router in _ROUTERS
            for method in (*_METHODS, "view")
        ),
        # ``app.add_routes([web.get('/', handler)])``: the route definitions name the handler.
        RouteRegistrar(_sym("aiohttp.web.route"), 2, "http", keyword="handler"),
        *(RouteRegistrar(_sym(f"aiohttp.web.{method}"), 1, "http", keyword="handler") for method in (*_METHODS, "view")),
        Sink(_sym("aiohttp.web.Response"), TaintKind.HTML),
        Sink(_sym("aiohttp.web.FileResponse"), TaintKind.PATH),
        *(Sink(_sym(f"aiohttp.web.{exception}"), TaintKind.REDIRECT) for exception in _REDIRECTS),
        *(Sink(_sym(f"aiohttp.web_exceptions.{exception}"), TaintKind.REDIRECT) for exception in _REDIRECTS),
        *(Sink(_sym(function), TaintKind.SSRF) for function in _CLIENT_FUNCTIONS),
        *(Source(_sym(function), "http-response") for function in _CLIENT_FUNCTIONS),
    )
