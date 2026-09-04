"""Acceptance tests for URL-registered views and ORM suffix sinks, motivated by
``tests-project/DjangoGoat`` (branch ``broken``).

Django views are plain functions registered elsewhere: ``path('login/', views.log_in)``
in ``urls.py``. A ``RouteRegistrar`` model names such a registering call and the argument
that references the view; the engine scans every module of the project for
registrations before analysing, so the registered functions, and the methods of a class
registered through ``as_view()`` or a REST framework router, are entry points wherever
they are defined. A ``SuffixSink`` matches a call by the tail of its symbol, so
``User.objects.raw(query)`` is a SQL sink whatever the model class.

Expected to remain red until ``RouteRegistrar``, ``SuffixSink``, ``taint.routes`` and
the Django, Flask and FastAPI registrar models exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import SecurityModelRegistry, Sink, TaintKind

try:
    from coretrace_python.taint import (
        RegisteredRoutes,
        RouteRegistrar,
        SuffixSink,
        registered_routes,
    )
except ImportError as error:  # pragma: no cover - red until routes land
    MISSING: Exception | None = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_routes() -> None:
    if MISSING is not None:
        pytest.fail(f"registered routes are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def located(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return sorted((Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings)


def check(text: str, name: str = "views.py") -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source(name, text), [PLUGINS])


DJANGO_VIEWS = (
    "import os\nfrom django.views import View\n\n"
    "def log_in(request):\n    os.system(request.POST['cmd'])\n\n"
    "def helper(request):\n    os.system(request.POST['cmd'])\n\n"
    "class NoteView(View):\n    def get(self, request, pk):\n        os.system(pk)\n"
)
DJANGO_URLS = (
    "from django.urls import path\nfrom app import views\n\n"
    "urlpatterns = [\n"
    "    path('login/', views.log_in, name='login'),\n"
    "    path('note/<pk>', views.NoteView.as_view(), name='note'),\n"
    "]\n"
)


# --------------------------------------------------------------------------- models


def test_registrars_and_suffix_sinks_are_indexed() -> None:
    registrar = RouteRegistrar(SymbolId("python.django.urls.path"), 1, "http")
    suffix = SuffixSink("objects.raw", TaintKind.SQL, ((TaintKind.SQL, (0,)),))
    registry = SecurityModelRegistry()
    registry.register(registrar, suffix, Sink(SymbolId("python.os.system"), TaintKind.COMMAND))
    table = registry.freeze()

    assert table.route_registrar(SymbolId("python.django.urls.path")) == registrar
    assert table.route_registrars == (registrar,)
    found = table.sink(SymbolId("python.django.contrib.auth.models.User.objects.raw"))
    assert found is not None and found.kinds == TaintKind.SQL and found.kinds_at(1) == TaintKind.NONE
    assert table.sink(SymbolId("python.os.raw")) is None
    assert table.sink(SymbolId("python.os.system")) is not None
    extended = table.extended(Sink(SymbolId("python.x"), TaintKind.ADVISORY))
    assert extended.route_registrars == (registrar,) and extended.suffix_sinks == (suffix,)
    assert RegisteredRoutes.name == "taint.routes"


def test_registrations_are_collected_from_a_module() -> None:
    from coretrace_python.semantic.scopes import ScopeAnalysis
    from coretrace_python.semantic.symbols import SymbolAnalysis

    module = build_hir(SourceManager().add_source("urls.py", DJANGO_URLS, module_name="app.urls"))
    manager = engine.build_manager(module)
    registry = SecurityModelRegistry()
    registry.register(RouteRegistrar(SymbolId("python.django.urls.path"), 1, "http"))

    routes = registered_routes(module, manager.get(ScopeAnalysis), manager.get(SymbolAnalysis), registry.freeze())

    assert {str(s): (e.label, str(e.symbol)) for s, e in routes.items()} == {
        "python.app.views.log_in": ("http", "python.django.urls.path"),
        "python.app.views.NoteView": ("http", "python.django.urls.path"),
    }


# --------------------------------------------------------------------------- registered views


def test_registered_django_views_and_class_based_views_are_entry_points(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/__init__.py": "", "app/views.py": DJANGO_VIEWS, "app/urls.py": DJANGO_URLS})

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert located(findings) == [("views.py", "command-injection", 5), ("views.py", "command-injection", 12)]
    assert {f.metadata["source_label"] for f in findings} == {"http"}


def test_registrations_in_the_same_module_and_aliased_imports_work(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "authentication/__init__.py": "",
            "authentication/views.py": "import os\n\ndef log_in(request):\n    os.system(request.POST['cmd'])\n",
            "site/__init__.py": "",
            "site/urls.py": "from django.urls import path, re_path\nfrom authentication import views as auth_views\n\n"
            "urlpatterns = [path('login/', auth_views.log_in, name='login')]\n",
            "local.py": "import os\nfrom django.urls import path\n\ndef ping(request):\n    os.system(request.GET['h'])\n\n"
            "urlpatterns = [path('ping/', ping)]\n",
        },
    )
    assert located(engine.analyze_project(root, [PLUGINS]).findings) == [
        ("local.py", "command-injection", 5),
        ("views.py", "command-injection", 4),
    ]


def test_rest_framework_routers_register_viewsets(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "api/__init__.py": "",
            "api/views.py": "import os\nfrom rest_framework import viewsets\n\n"
            "class Ping(viewsets.ViewSet):\n    def list(self, request):\n        os.system(request.query_params['h'])\n",
            "api/urls.py": "from rest_framework.routers import DefaultRouter\nfrom api.views import Ping\n\n"
            "router = DefaultRouter()\nrouter.register(r'ping', Ping, basename='ping')\nurlpatterns = router.urls\n",
        },
    )
    assert located(engine.analyze_project(root, [PLUGINS]).findings) == [("views.py", "command-injection", 6)]


def test_flask_and_fastapi_programmatic_registration(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "flask_app.py": "import os\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
            "def run():\n    os.system(request.args['c'])\n\n"
            "app.add_url_rule('/run', view_func=run)\n",
            "fast_app.py": "import os\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n"
            "def ping(host: str):\n    os.system(host)\n\n"
            "app.add_api_route('/ping', ping)\n",
        },
    )
    assert located(engine.analyze_project(root, [PLUGINS]).findings) == [
        ("fast_app.py", "command-injection", 7),
        ("flask_app.py", "command-injection", 7),
    ]


def test_unregistered_functions_stay_clean() -> None:
    assert check("import os\n\ndef helper(request):\n    os.system(request.POST['cmd'])\n") == ()


# --------------------------------------------------------------------------- suffix sinks


def test_model_raw_queries_are_sql_sinks(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/models.py": "from django.db import models\n\nclass Note(models.Model):\n    body = models.TextField()\n",
            "app/views.py": "from django.contrib.auth.models import User\nfrom app.models import Note\n\n"
            "def log_in(request):\n"
            "    username = request.POST['username']\n"
            "    query = \"SELECT * FROM auth_user WHERE username = '%s'\" % (username,)\n"
            "    user = User.objects.raw(query)[0]\n"
            "    notes = Note.objects.raw('SELECT * FROM app_note WHERE body = %s', [username])\n"
            "    unsafe = Note.objects.raw('SELECT * FROM app_note WHERE body = ' + username)\n"
            "    return user, notes, unsafe\n",
            "app/urls.py": "from django.urls import path\nfrom app import views\n\nurlpatterns = [path('login/', views.log_in)]\n",
        },
    )
    assert located(engine.analyze_project(root, [PLUGINS]).findings) == [
        ("views.py", "sql-injection", 7),
        ("views.py", "sql-injection", 9),
    ]


# --------------------------------------------------------------------------- engine plumbing


def test_routes_are_part_of_the_cache_key_and_reach_workers(tmp_path: Path) -> None:
    root = project(tmp_path, {"app/__init__.py": "", "app/views.py": DJANGO_VIEWS, "app/urls.py": "urlpatterns = []\n"})
    cache = ProjectCache(tmp_path / "cache")
    before = engine.analyze_project(root, [PLUGINS], cache=cache)
    (root / "app" / "urls.py").write_text(DJANGO_URLS, encoding="utf-8")
    after = engine.analyze_project(root, [PLUGINS], cache=cache)
    parallel = engine.analyze_project(root, [PLUGINS], jobs=2)

    # The class-based view derives from ``View``, an entry point in itself; the function
    # view only becomes one once ``urls.py`` registers it.
    assert located(before.findings) == [("views.py", "command-injection", 12)]
    assert before.keys["app.views"] != after.keys["app.views"]
    assert located(after.findings) == [("views.py", "command-injection", 5), ("views.py", "command-injection", 12)]
    assert parallel.findings == after.findings
