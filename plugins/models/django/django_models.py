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
from coretrace_python.taint import EntryPoint, Model, Sanitizer, Sink, TaintKind, TypedParameter

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


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class DjangoModels(ModelPlugin):
    name: ClassVar[str] = "django-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(TypedParameter(_sym(cls), "http") for cls in _REQUEST_CLASSES),
        *(EntryPoint(_sym(base), "http") for base in _VIEW_BASES),
        *(EntryPoint(_sym(decorator), "http") for decorator in _VIEW_DECORATORS),
        Sink(_sym("django.db.connection.cursor.execute"), TaintKind.SQL),
        Sink(_sym("django.db.connection.cursor.executemany"), TaintKind.SQL),
        Sink(_sym("django.db.models.expressions.RawSQL"), TaintKind.SQL),
        Sink(_sym("django.db.models.Manager.raw"), TaintKind.SQL),
        Sink(_sym("django.db.models.QuerySet.raw"), TaintKind.SQL),
        Sink(_sym("django.db.models.QuerySet.extra"), TaintKind.SQL),
        Sink(_sym("django.utils.safestring.mark_safe"), TaintKind.HTML),
        Sink(_sym("django.http.HttpResponse"), TaintKind.HTML),
        Sink(_sym("django.http.response.HttpResponse"), TaintKind.HTML),
        Sink(_sym("django.template.Template"), TaintKind.HTML),
        Sink(_sym("django.http.FileResponse"), TaintKind.PATH),
        Sanitizer(_sym("django.utils.html.escape"), TaintKind.HTML),
        Sanitizer(_sym("django.utils.html.conditional_escape"), TaintKind.HTML),
    )
