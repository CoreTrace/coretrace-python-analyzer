"""Acceptance tests for issue #288: the positions of a template's filters, includes and
loads are found in time linear in the template.

Each position was counted from the start of the file, so collecting the filters of a
template applying n of them took time quadratic in its size, where Django compiles and
renders it in linear time. The start of each line of a template is now found once, when
it is read, and each position by bisection.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TIMEOUT = 60
COUNT = 200_000
# The template's number of filters and the last one's line and column, then the number
# of unread entries and the last one.
DESCRIBE = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from coretrace_python.taint.templates import project_templates\n"
    "found = project_templates(Path(sys.argv[1]))\n"
    "filters = found.filters.get('page.html', ())\n"
    "last = [filters[-1].location.start_line, filters[-1].location.start_column] if filters else None\n"
    "print(json.dumps([len(filters), last, len(found.unread), found.unread[-1:]]))\n"
)


@pytest.mark.parametrize(
    ("unit", "expected"),
    [
        ("{{ v|upper }}", [COUNT, [1, 13 * (COUNT - 1) + 6], 0, []]),
        (
            "{% include v %}\n",
            [0, None, COUNT, [f"app/templates/page.html:{COUNT} names a template by an expression"]],
        ),
        (
            "{% load missing %}{{ v|upper }}\n",
            [0, None, COUNT, [f"app/templates/page.html:{COUNT} loads 'missing', not found"]],
        ),
    ],
    ids=["filters-on-one-line", "includes-named-by-an-expression", "loads-not-found"],
)
def test_the_positions_in_a_large_template_are_found_in_linear_time(
    tmp_path: Path, unit: str, expected: list[object]
) -> None:
    # Counted from the start of the file each time, these positions took minutes.
    templates = tmp_path / "app" / "templates"
    templates.mkdir(parents=True)
    (templates / "page.html").write_text(unit * COUNT, encoding="utf-8")
    try:
        completed = subprocess.run(
            [sys.executable, "-c", DESCRIBE, str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"finding the positions did not end within {TIMEOUT} s")

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == expected
