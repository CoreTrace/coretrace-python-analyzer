"""Acceptance tests for issue #245: with ``-j N``, a worker process prepares the project
once and reads each imported module's summaries once.

Every component used to rebuild the plugins, the dependencies, the advisories and the
models in its worker, and to be sent the summaries of every module it imports,
transitively, encoded again by the parent for each component: ``-j N`` was slower than
``-j 1`` on real projects. The report does not depend on the number of processes.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache

COUNTER_MANIFEST = (
    'name = "counter"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = []\n\n[entrypoint]\nmodule = "counter"\nclass = "Counter"\n'
)
# Each process that loads the plugins instantiates this one, and says so.
COUNTER = '''
import os
from pathlib import Path
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin


class Counter(ModelPlugin):
    name: ClassVar[str] = "counter"

    def __init__(self) -> None:
        super().__init__()
        with (Path(__file__).parent / "instances.log").open("a", encoding="utf-8") as log:
            log.write(f"{os.getpid()}\\n")
'''

# Eight modules importing nothing of each other: eight components in one wave.
INDEPENDENT = {f"app/m{index}.py": f"def run{index}(value):\n    return value\n" for index in range(8)}

# ``views`` reaches ``os.system`` only through the summary of ``helpers``, analysed in an
# earlier wave, and ``more`` through the summary of ``views``.
LAYERED = {
    "app/__init__.py": "",
    "app/helpers.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n",
    "app/views.py": (
        "from flask import request\n\nfrom app.helpers import run\n\n\n"
        "def view():\n    run(request.args['c'])\n\n\ndef forward(cmd):\n    run(cmd)\n"
    ),
    "app/more.py": "from flask import request\n\nfrom app.views import forward\n\n\ndef again():\n    forward(request.args['c'])\n",
}


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def findings(analysis: engine.ProjectAnalysis) -> list[tuple[str, str, int, str | None]]:
    return sorted(
        (f.rule_id, Path(str(f.span.source_id)).name, f.span.start_line, f.metadata.get("verdict"))
        for f in analysis.findings
    )


def test_a_worker_prepares_the_project_once(tmp_path: Path) -> None:
    plugin = tmp_path / "plugins" / "counter"
    plugin.mkdir(parents=True)
    (plugin / "plugin.toml").write_text(COUNTER_MANIFEST, encoding="utf-8")
    (plugin / "counter.py").write_text(COUNTER, encoding="utf-8")
    root = write(tmp_path / "project", INDEPENDENT)

    engine.analyze_project(root, [engine.BUNDLED_PLUGINS, tmp_path / "plugins"], jobs=2)

    loads = (plugin / "instances.log").read_text(encoding="utf-8").split()
    in_workers = [pid for pid in loads if pid != str(os.getpid())]
    assert in_workers
    assert len(in_workers) == len(set(in_workers)) <= 2


@pytest.mark.parametrize("cached", [False, True], ids=["no-cache", "cache"])
def test_summaries_reach_the_modules_of_later_waves(tmp_path: Path, cached: bool) -> None:
    root = write(tmp_path / "project", LAYERED)
    cache = ProjectCache(tmp_path / "cache") if cached else None

    sequential = findings(engine.analyze_project(root, [engine.BUNDLED_PLUGINS]))
    parallel = findings(engine.analyze_project(root, [engine.BUNDLED_PLUGINS], jobs=2, cache=cache))

    assert parallel == sequential
    assert [f for f in parallel if f[0] == "command-injection"] == [
        ("command-injection", "more.py", 7, "vulnerability"),
        ("command-injection", "views.py", 7, "vulnerability"),
    ]
