"""Django security models: typed requests, views, decorators, ORM and HTML sinks.

Django views are undecorated, so HTTP input comes from three generic mechanisms: a
parameter annotated with a request class, a method of a class-based view, or a view
decorated by one of Django's or Django REST framework's view decorators. A view with a
bare ``request`` parameter and none of these is not recognised; URL configurations are
not read.
"""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import (
    AuthorizationGuard,
    EntryPoint,
    Model,
    RequestObject,
    RouteRegistrar,
    Sanitizer,
    Sink,
    Source,
    SuffixSink,
    TaintKind,
    TemplateRender,
    TypedParameter,
)

_REQUEST_CLASSES = (
    "django.http.HttpRequest",
    "django.http.request.HttpRequest",
    "django.core.handlers.wsgi.WSGIRequest",
    "django.core.handlers.asgi.ASGIRequest",
    "rest_framework.request.Request",
)

_VIEW_BASES = (
    "django.views.View",
    "django.views.generic.View",
    "django.views.generic.base.View",
    "django.views.generic.TemplateView",
    "django.views.generic.RedirectView",
    "django.views.generic.ListView",
    "django.views.generic.DetailView",
    "django.views.generic.FormView",
    "django.views.generic.CreateView",
    "django.views.generic.UpdateView",
    "django.views.generic.DeleteView",
    "rest_framework.views.APIView",
    "rest_framework.generics.GenericAPIView",
    "rest_framework.viewsets.ViewSet",
    "rest_framework.viewsets.GenericViewSet",
    "rest_framework.viewsets.ModelViewSet",
    "rest_framework.viewsets.ReadOnlyModelViewSet",
)

_VIEW_DECORATORS = (
    "django.views.decorators.csrf.csrf_exempt",
    "django.views.decorators.csrf.csrf_protect",
    "django.views.decorators.http.require_http_methods",
    "django.views.decorators.http.require_GET",
    "django.views.decorators.http.require_POST",
    "django.views.decorators.http.require_safe",
    "django.views.decorators.cache.never_cache",
    "django.views.decorators.cache.cache_page",
    "django.contrib.auth.decorators.login_required",
    "django.contrib.auth.decorators.permission_required",
    "django.contrib.auth.decorators.user_passes_test",
    "rest_framework.decorators.api_view",
    "rest_framework.decorators.action",
)

_ROUTE_REGISTRARS = (
    "django.urls.path",
    "django.urls.re_path",
    "django.conf.urls.url",
    "rest_framework.routers.DefaultRouter.register",
    "rest_framework.routers.SimpleRouter.register",
)

_AUTHORIZATION_DECORATORS = (
    ("django.contrib.auth.decorators.login_required", "login"),
    ("django.contrib.auth.decorators.permission_required", "permission"),
    ("django.contrib.auth.decorators.user_passes_test", "test"),
    ("django.contrib.admin.views.decorators.staff_member_required", "staff"),
    ("rest_framework.decorators.permission_classes", "permission"),
)


# What a request object gives as text: the query string, form fields, headers, cookies
# and path. Its body, its files and REST framework's parsed ``data`` may hold a structure.
_REQUEST_TEXT = (
    "GET", "POST", "COOKIES", "META", "headers", "path", "path_info", "method", "scheme", "encoding",
    "content_type", "content_params", "resolver_match", "get_full_path", "get_full_path_info",
    "build_absolute_uri", "get_host", "get_port", "get_signed_cookie", "query_params",
)
# Every input a request object comes from: an annotated parameter, a class-based view's
# method or ``self.request``, a decorated view, a view registered in a URL configuration.
_REQUEST_INPUTS = (
    *_REQUEST_CLASSES,
    *_VIEW_BASES,
    *(f"{base}.request" for base in _VIEW_BASES),
    *_VIEW_DECORATORS,
    *_ROUTE_REGISTRARS,
)

_TARGET_ONLY = ((TaintKind.REDIRECT, (0,)),)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class DjangoModels(ModelPlugin):
    name: ClassVar[str] = "django-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(TypedParameter(_sym(cls), "http") for cls in _REQUEST_CLASSES),
        *(EntryPoint(_sym(base), "http") for base in _VIEW_BASES),
        # ``self.request`` in a class-based view: the attribute is inherited from the base.
        *(Source(_sym(f"{base}.request"), "http") for base in _VIEW_BASES),
        *(EntryPoint(_sym(decorator), "http") for decorator in _VIEW_DECORATORS),
        *(RequestObject(_sym(symbol), _REQUEST_TEXT) for symbol in _REQUEST_INPUTS),
        Sink(_sym("django.db.connection.cursor.execute"), TaintKind.SQL | TaintKind.CREDENTIAL, ((TaintKind.SQL, (0,)),)),
        Sink(_sym("django.db.connection.cursor.executemany"), TaintKind.SQL | TaintKind.CREDENTIAL, ((TaintKind.SQL, (0,)),)),
        Sink(_sym("django.db.models.expressions.RawSQL"), TaintKind.SQL | TaintKind.CREDENTIAL),
        Sink(_sym("django.db.models.Manager.raw"), TaintKind.SQL | TaintKind.CREDENTIAL),
        Sink(_sym("django.db.models.QuerySet.raw"), TaintKind.SQL | TaintKind.CREDENTIAL),
        Sink(_sym("django.db.models.QuerySet.extra"), TaintKind.SQL | TaintKind.CREDENTIAL),
        Sink(_sym("django.utils.safestring.mark_safe"), TaintKind.HTML),
        Sink(_sym("django.http.HttpResponse"), TaintKind.HTML),
        Sink(_sym("django.http.response.HttpResponse"), TaintKind.HTML),
        Sink(_sym("django.template.Template"), TaintKind.HTML),
        Sink(_sym("django.http.FileResponse"), TaintKind.PATH),
        # Only the target is a redirect: the other arguments of ``redirect`` are route
        # parameters resolved through the URL configuration.
        Sink(_sym("django.shortcuts.redirect"), TaintKind.REDIRECT, _TARGET_ONLY),
        Sink(_sym("django.http.HttpResponseRedirect"), TaintKind.REDIRECT, _TARGET_ONLY),
        Sink(_sym("django.http.HttpResponsePermanentRedirect"), TaintKind.REDIRECT, _TARGET_ONLY),
        Sanitizer(_sym("django.utils.html.escape"), TaintKind.HTML),
        TemplateRender(_sym("django.template.loader.render_to_string")),
        Sanitizer(_sym("django.utils.html.conditional_escape"), TaintKind.HTML),
        # The masked CSRF secret: ASCII letters and digits only, a malformed cookie is
        # replaced before it is used.
        Sanitizer(_sym("django.middleware.csrf.get_token"), TaintKind.ALL),
        # A path of the project's URL configuration, never scheme-relative: attacker data
        # in its arguments or query reaches no other host through a redirect.
        *(Sanitizer(_sym(f"django.urls.{name}"), TaintKind.REDIRECT) for name in ("reverse", "reverse_lazy")),
        *(Sanitizer(_sym(f"django.urls.base.{name}"), TaintKind.REDIRECT) for name in ("reverse", "reverse_lazy")),
        *(AuthorizationGuard(_sym(decorator), label) for decorator, label in _AUTHORIZATION_DECORATORS),
        # ``urlpatterns = [path('login/', views.log_in)]``: the referenced view is an
        # entry point wherever it is defined; routers register viewsets.
        *(RouteRegistrar(_sym(registrar), 1, "http") for registrar in _ROUTE_REGISTRARS),
        # ``Model.objects.raw(sql)`` for any model class: the statement is the first
        # argument, its parameters are not.
        SuffixSink("objects.raw", TaintKind.SQL, ((TaintKind.SQL, (0,)),)),
        SuffixSink("objects.extra", TaintKind.SQL),
    )
