"""Acceptance tests for issue #240, part 1: the dynamic import and module-execution APIs
are ``code-injection`` sinks.

``importlib.import_module``, ``__import__`` and ``runpy.run_module`` import or run a module
the input chooses among those that can be found; ``runpy.run_path`` runs the file the
input chooses. Only the argument naming the module or the file is a sink, by position
or keyword; the globals and the run name are data. A constant package prefix confines
the input to the modules of that package: a hotspot. The environment and the command
line reach these sinks as they reach ``eval``.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from coretrace_python.cli import main

APP = """\
import importlib
import os
import runpy
import sys

from flask import Flask, request

app = Flask(__name__)
SCRIPTS = "/srv/scripts"


def load(name):
    return importlib.import_module(name)


@app.route("/import-module")
def import_module():
    return importlib.import_module(request.args["m"])


@app.route("/import-module-keyword")
def import_module_keyword():
    return importlib.import_module(name=request.args["m"])


@app.route("/import-module-package")
def import_module_package():
    return importlib.import_module(request.args["m"], package="app")


@app.route("/builtin-import")
def builtin_import():
    return __import__(request.args["m"])


@app.route("/importlib-import")
def importlib_import():
    return importlib.__import__(request.args["m"])


@app.route("/run-module")
def run_module():
    return runpy.run_module(request.args["m"])


@app.route("/run-path")
def run_path():
    return runpy.run_path(request.args["p"])


@app.route("/run-path-directory")
def run_path_directory():
    return runpy.run_path(os.path.join(SCRIPTS, request.args["p"]))


@app.route("/through-helper")
def through_helper():
    return load(request.args["m"])


@app.route("/package-prefix")
def package_prefix():
    return importlib.import_module("app.plugins." + request.args["m"])


@app.route("/package-prefix-format")
def package_prefix_format():
    return importlib.import_module(f"app.plugins.{request.args['m']}")


@app.route("/constant-name")
def constant_name():
    return importlib.import_module("json")


@app.route("/allowlisted-name")
def allowlisted_name():
    name = request.args["m"]
    if name in ("csv", "json"):
        return importlib.import_module(name)


@app.route("/data-arguments-only")
def data_arguments_only():
    return runpy.run_path("jobs/report.py", init_globals={"q": request.args["q"]}, run_name=request.args["n"])


def settings_module():
    return importlib.import_module(os.environ["DJANGO_SETTINGS_MODULE"])


def plugin_from_command_line():
    return importlib.import_module(sys.argv[1])


def evaluate_environment():
    return eval(os.environ["EXPRESSION"])


def evaluate_command_line():
    return eval(sys.argv[1])
"""

IMPORT = ("vulnerability", "high", "Untrusted module import")
SCRIPT = ("vulnerability", "high", "Untrusted script execution")
EVAL = ("vulnerability", "high", "Code injection")

EXPECTED = {
    "import_module": IMPORT,
    "import_module_keyword": IMPORT,
    "import_module_package": IMPORT,
    "builtin_import": IMPORT,
    "importlib_import": IMPORT,
    "run_module": IMPORT,
    "run_path": SCRIPT,
    "run_path_directory": SCRIPT,
    "through_helper": IMPORT,
    "package_prefix": ("hotspot", "medium", "Untrusted module import"),
    "package_prefix_format": ("hotspot", "medium", "Untrusted module import"),
    "constant_name": None,
    "allowlisted_name": None,
    "data_arguments_only": None,
    # The environment and the command line carry ``CODE`` (#240, decided).
    "settings_module": IMPORT,
    "plugin_from_command_line": IMPORT,
    "evaluate_environment": EVAL,
    "evaluate_command_line": EVAL,
}


@pytest.fixture(scope="module")
def reported(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[str, str, str]]:
    root = tmp_path_factory.mktemp("dynamic_imports")
    (root / "app.py").write_text(APP, encoding="utf-8")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["--check", str(root), "--format", "json"])
    found: dict[str, tuple[str, str, str]] = {}
    for finding in json.loads(out.getvalue())["findings"]:
        if finding["rule_id"] != "code-injection":
            continue
        assert finding["function"] not in found, finding
        title = finding["message"].split(":", 1)[0]
        found[finding["function"]] = (finding["metadata"]["verdict"], finding["confidence"], title)
    return found


@pytest.mark.parametrize("function", sorted(EXPECTED))
def test_dynamic_import_verdict(reported: dict[str, tuple[str, str, str]], function: str) -> None:
    assert reported.get(function) == EXPECTED[function]


def test_every_reported_function_is_expected(reported: dict[str, tuple[str, str, str]]) -> None:
    assert set(reported) <= set(EXPECTED)
