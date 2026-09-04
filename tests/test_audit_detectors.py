"""Acceptance tests for the detectors the ``tests-project/SECURITY_AUDIT.md`` review asked
for, each traced to a line of one of the twelve repositories.

- Advisories for Gunicorn, OpenCV, Werkzeug and Pillow with their affected APIs, so the
  vulnerable requirements and the reachable calls (``cv2.imread``, ``PIL.Image.open``)
  are reported (uploadbox, Flask-Image-Editing-Website, MiniBookApiServer).
- ``app.run(debug=True)``, at module level too (Flask-Image-Editing-Website, Spam-Detection).
- HTTP client calls without a ``timeout`` (Chatbot).
- The output of a subprocess is an untrusted source: ``sh`` fed with ``curl``'s stdout
  is a command injection (Chatbot ``setup.py``).
- Credentials inside a URL literal, in a parameter default too (Pylinkit).
- The fallback value of ``os.getenv("..._TOKEN", "literal")`` is a hardcoded credential
  (tag-collector-server).

Expected to remain red until the plugins ``syntax/flask_debug`` and
``syntax/missing_timeout`` and the model and pattern additions exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.frontend import build_hir
from coretrace_python.plugins import discover_plugins
from coretrace_python.plugins.secrets import literals
from coretrace_python.source import SourceManager

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


@pytest.fixture(autouse=True)
def require_plugins() -> None:
    module = build_hir(SourceManager().add_source("empty.py", ""))
    names = {p.manifest.name for p in discover_plugins(PLUGINS, engine.build_manager(module))}
    missing = {"flask-debug", "missing-timeout"} - names
    if missing:
        pytest.fail(f"audit detectors are not implemented yet: {sorted(missing)}")


def check(text: str, name: str = "app.py") -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source(name, text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int]]:
    return sorted((f.rule_id, f.span.start_line) for f in findings)


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def project_rules(root: Path) -> list[tuple[str, str, int]]:
    findings = engine.analyze_project(root, [PLUGINS]).findings
    return sorted((f.rule_id, Path(str(f.span.source_id)).name, f.span.start_line) for f in findings)


# --------------------------------------------------------------------------- advisories


def test_audit_cited_advisories_are_shipped_with_affected_apis() -> None:
    module = build_hir(SourceManager().add_source("empty.py", ""))
    loaded = {p.manifest.name: p for p in discover_plugins(PLUGINS, engine.build_manager(module))}
    advisories = {a.id: a for a in loaded["sample-advisories"].plugin.advisories}

    assert advisories["CVE-2024-1135"].package == "gunicorn" and advisories["CVE-2024-1135"].vulnerable == "<22.0.0"
    assert advisories["CVE-2023-4863"].package == "opencv-python"
    assert "python.cv2.imread" in {str(s) for s in advisories["CVE-2023-4863"].affected_symbols}
    assert advisories["CVE-2024-34069"].package == "werkzeug" and advisories["CVE-2024-34069"].vulnerable == "<3.0.3"
    assert advisories["CVE-2023-46136"].package == "werkzeug"
    assert advisories["CVE-2026-25990"].package == "pillow"
    assert "python.PIL.Image.open" in {str(s) for s in advisories["CVE-2026-25990"].affected_symbols}


def test_image_processing_with_a_vulnerable_opencv_is_reachable(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "Flask==2.3.2\nopencv-python==4.8.0.74\nWerkzeug==2.3.6\n",
            "main.py": "import cv2\n\ndef process(filename):\n    return cv2.imread(filename)\n",
        },
    )
    assert project_rules(root) == [
        ("reachable-vulnerability", "main.py", 4),
        ("vulnerable-dependency", "requirements.txt", 2),
        ("vulnerable-dependency", "requirements.txt", 3),
        ("vulnerable-dependency", "requirements.txt", 3),
    ]


def test_pillow_and_gunicorn_requirements_are_reported(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "pillow==11.2.1\ngunicorn==20.0.3\n",
            "res.py": "from PIL import Image\n\ndef load(data):\n    return Image.open(data)\n",
        },
    )
    assert project_rules(root) == [
        ("reachable-vulnerability", "res.py", 4),
        ("vulnerable-dependency", "requirements.txt", 1),
        ("vulnerable-dependency", "requirements.txt", 2),
    ]


# --------------------------------------------------------------------------- flask debug


def test_flask_debug_is_reported_at_module_level_and_in_functions() -> None:
    findings = check(
        "from flask import Flask\n\napp = Flask(__name__)\n\n"
        "def main():\n    app.run(host='0.0.0.0', debug=True)\n\n"
        "app.run(debug=True)\n"
        "app.run(debug=False)\n"
        "app.run()\n"
    )
    debug = [f for f in findings if f.rule_id == "debug-enabled"]
    assert [f.span.start_line for f in debug] == [6, 8]
    assert debug[0].severity is Severity.HIGH and debug[0].confidence is Confidence.HIGH
    assert debug[0].function == "main" and debug[1].function is None
    assert "debugger" in debug[0].message


def test_debug_on_other_objects_is_ignored() -> None:
    assert check("class App:\n    def run(self, debug):\n        pass\n\napp = App()\napp.run(debug=True)\n") == ()


# --------------------------------------------------------------------------- timeouts


def test_http_calls_without_a_timeout_are_reported() -> None:
    findings = check(
        "import requests\nimport httpx\n\nsession = requests.Session()\n\n"
        "def fetch(url):\n"
        "    requests.get(url)\n"
        "    requests.post(url, timeout=5)\n"
        "    session.get(url)\n"
        "    httpx.get(url, timeout=None)\n"
        "    client = httpx.Client()\n"
        "    client.get(url)\n"
    )
    timeouts = [f for f in findings if f.rule_id == "missing-timeout"]
    assert [(f.span.start_line, f.metadata["symbol"]) for f in timeouts] == [
        (7, "python.requests.get"),
        (9, "python.requests.Session.get"),
        (12, "python.httpx.Client.get"),
    ]
    assert timeouts[0].severity is Severity.LOW


# --------------------------------------------------------------------------- process output


def test_subprocess_output_is_an_untrusted_source() -> None:
    findings = check(
        "import subprocess\n\n"
        "def install():\n"
        "    result = subprocess.run(['curl', '-fsSL', 'https://example.com/install.sh'], capture_output=True)\n"
        "    subprocess.run(['sh'], input=result.stdout, check=True)\n"
    )
    (finding,) = [f for f in findings if f.rule_id == "command-injection"]
    assert finding.span.start_line == 5
    assert finding.metadata["source_label"] == "process-output"


def test_check_output_is_a_source_too() -> None:
    findings = check("import os\nimport subprocess\n\ndef f():\n    os.system(subprocess.check_output(['ls']))\n")
    assert rules(findings) == [("command-injection", 5)]


# --------------------------------------------------------------------------- secrets


def test_credentials_in_urls_are_secrets_including_parameter_defaults() -> None:
    findings = check(
        "import requests\n\n"
        "def sync(url='http://host.example/api?login=LIAM&password=LIAM&application=x'):\n"
        "    return requests.get(url, timeout=3)\n\n"
        "DB = 'postgres://admin:hunter2@db.example/app'\n"
        "SAFE = 'https://host.example/api?page=2'\n"
    )
    secrets = [f for f in findings if f.rule_id == "hardcoded-secret"]
    assert [(f.span.start_line, f.metadata["provider"], f.metadata["name"]) for f in secrets] == [
        (3, "url", "url"),
        (6, "url", "DB"),
    ]
    assert all("hunter2" not in f.message and "LIAM" not in f.message for f in secrets)


def test_environment_fallbacks_are_credentials() -> None:
    module = build_hir(
        SourceManager().add_source(
            "conf.py",
            "import os\n"
            "TOKEN = os.getenv('INFLUXDB_INIT_ADMIN_TOKEN', 'mon-token-secret')\n"
            "URL = os.environ.get('INFLUXDB_INIT_URL', 'http://localhost:8086')\n"
            "NAME = os.getenv('APP_NAME')\n",
        )
    )
    found = [(value, name) for value, name, _, _ in literals(module)]
    assert found == [
        ("INFLUXDB_INIT_ADMIN_TOKEN", None),
        ("mon-token-secret", "INFLUXDB_INIT_ADMIN_TOKEN"),
        ("INFLUXDB_INIT_URL", None),
        ("http://localhost:8086", "INFLUXDB_INIT_URL"),
        ("APP_NAME", None),
    ]
    findings = check("import os\nTOKEN = os.getenv('INFLUXDB_INIT_ADMIN_TOKEN', 'mon-token-secret')\n")
    assert [(f.rule_id, f.metadata["name"]) for f in findings] == [("hardcoded-credential", "INFLUXDB_INIT_ADMIN_TOKEN")]
