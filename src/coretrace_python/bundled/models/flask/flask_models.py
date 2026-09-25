"""Flask security models: HTTP sources, route handlers, HTML sinks and escaping."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import (
    TEXT_KINDS,
    AuthorizationGuard,
    EntryPoint,
    Model,
    RouteRegistrar,
    Sanitizer,
    Sink,
    Source,
    TaintKind,
)

# Strings, or mappings of strings: text, which cannot hold a query operator.
_TEXT_ATTRIBUTES = ("args", "form", "values", "cookies", "headers", "url", "full_path", "path", "query_string")
# JSON, and the raw bodies and files a ``json.loads`` may decode into a structure.
_PAYLOAD_ATTRIBUTES = ("json", "get_json", "data", "get_data", "stream", "files")


_TARGET_ONLY = ((TaintKind.REDIRECT, (0,)),)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class FlaskModels(ModelPlugin):
    name: ClassVar[str] = "flask-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(Source(_sym(f"flask.request.{attribute}"), "http", TEXT_KINDS) for attribute in _TEXT_ATTRIBUTES),
        *(Source(_sym(f"flask.request.{attribute}"), "http") for attribute in _PAYLOAD_ATTRIBUTES),
        # A route's parameters are segments of its URL.
        EntryPoint(_sym("flask.Flask.route"), "http", TEXT_KINDS),
        EntryPoint(_sym("flask.Blueprint.route"), "http", TEXT_KINDS),
        RouteRegistrar(_sym("flask.Flask.add_url_rule"), 2, "http", TEXT_KINDS, keyword="view_func"),
        RouteRegistrar(_sym("flask.Blueprint.add_url_rule"), 2, "http", TEXT_KINDS, keyword="view_func"),
        Sink(_sym("flask.render_template_string"), TaintKind.HTML),
        Sink(_sym("flask.make_response"), TaintKind.HTML),
        Sink(_sym("flask.Response"), TaintKind.HTML),
        Sink(_sym("flask.Markup"), TaintKind.HTML),
        Sink(_sym("flask.send_file"), TaintKind.PATH),
        # ``redirect(location, code)``: the status code is not a target.
        Sink(_sym("flask.redirect"), TaintKind.REDIRECT, _TARGET_ONLY),
        Sink(_sym("werkzeug.utils.redirect"), TaintKind.REDIRECT, _TARGET_ONLY),
        Sink(_sym("flask.request.files.save"), TaintKind.PATH),
        Sanitizer(_sym("werkzeug.utils.secure_filename"), TaintKind.PATH),
        Sanitizer(_sym("flask.escape"), TaintKind.HTML),
        Sanitizer(_sym("markupsafe.escape"), TaintKind.HTML),
        AuthorizationGuard(_sym("flask_login.login_required"), "login"),
        AuthorizationGuard(_sym("flask_login.fresh_login_required"), "login"),
        AuthorizationGuard(_sym("flask_login.current_user.is_authenticated"), "login"),
        AuthorizationGuard(_sym("flask.session"), "session"),
    )
