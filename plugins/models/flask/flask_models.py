"""Flask security models: HTTP sources, route handlers, HTML sinks and escaping."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import (
    AuthorizationGuard,
    EntryPoint,
    Model,
    Sanitizer,
    Sink,
    Source,
    TaintKind,
)

_REQUEST_ATTRIBUTES = (
    "args", "form", "values", "json", "data", "cookies", "headers", "files",
    "get_json", "get_data", "url", "full_path", "path", "query_string", "stream",
)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class FlaskModels(ModelPlugin):
    name: ClassVar[str] = "flask-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(Source(_sym(f"flask.request.{attribute}"), "http") for attribute in _REQUEST_ATTRIBUTES),
        EntryPoint(_sym("flask.Flask.route"), "http"),
        EntryPoint(_sym("flask.Blueprint.route"), "http"),
        Sink(_sym("flask.render_template_string"), TaintKind.HTML),
        Sink(_sym("flask.make_response"), TaintKind.HTML),
        Sink(_sym("flask.Response"), TaintKind.HTML),
        Sink(_sym("flask.Markup"), TaintKind.HTML),
        Sink(_sym("flask.send_file"), TaintKind.PATH),
        Sanitizer(_sym("flask.escape"), TaintKind.HTML),
        Sanitizer(_sym("markupsafe.escape"), TaintKind.HTML),
        AuthorizationGuard(_sym("flask_login.login_required"), "login"),
        AuthorizationGuard(_sym("flask_login.fresh_login_required"), "login"),
        AuthorizationGuard(_sym("flask_login.current_user.is_authenticated"), "login"),
    )
