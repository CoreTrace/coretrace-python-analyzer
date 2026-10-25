"""Acceptance tests for issue #284: a cycle of includes does not stop the collection of the
filters a template's render reaches.

A template reached again on the way contributes what it reaches, as Django renders it
when the project's conditions let the cycle turn: the filters of each template, with the
blocks the templates extending it override, are the least fixpoint of what it applies and
what its references reach through their bindings. Each expectation below is what Django
5.1.15 applies when it renders the same templates.
"""

from __future__ import annotations

import itertools
import json
import random
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories
from coretrace_python.findings import Severity
from coretrace_python.interprocedural import discover_files
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceId
from coretrace_python.taint import templates
from coretrace_python.taint.templates import project_templates

TIMEOUT = 60
FILTERS = "python.django.template.defaultfilters"
STRIPTAGS = f"{FILTERS}.striptags"
ADVISORY = Advisory(
    "CVE-2099-8401",
    "django",
    "<4.2.17",
    "striptags is quadratic in its input",
    Severity.MEDIUM,
    entry_points=(AdvisoryEntryPoint(SymbolId(STRIPTAGS), "a template filter"),),
)
LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "django" }]

[[package]]
name = "django"
version = "4.2.16"
source = { registry = "https://pypi.org/simple" }
"""
# The child extends the parent and overrides its body; the parent includes the child in
# that body, binding v to other. Django renders b.html as striptags of v, then, through
# a.html, b.html again with the body overridden: striptags of other, then upper of other.
CYCLE = {
    "app/templates/a.html": "{% extends 'b.html' %}\n{% block body %}{{ v|upper }}{% endblock %}\n",
    "app/templates/b.html": "{{ v|striptags }}\n{% block body %}{% include 'a.html' with v=other %}{% endblock %}\n",
}


def write(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def exploitable(root: Path, context: str) -> list[tuple[int, str, str]]:
    """The exploitable striptags calls a view rendering b.html with ``context`` makes: the
    render line, the template holding the filter, and the line of the filter there."""

    view = (
        "from django.http import HttpRequest\n"
        "from django.shortcuts import render\n\n"
        "def page(request: HttpRequest):\n"
        f"    return render(request, 'b.html', {context})\n"
    )
    write(root, {"uv.lock": LOCK, "app/__init__.py": "", "app/views.py": view, **CYCLE})
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    return sorted(
        (f.span.start_line, f.metadata["through"], f.metadata["sink_line"])
        for f in findings
        if f.rule_id == "exploitable-vulnerability" and f.metadata["advisory"] == ADVISORY.id
    )


@pytest.mark.parametrize(
    "context",
    ["{'v': 'fixed', 'other': request.POST['bio']}", "{'v': request.POST['bio'], 'other': 'fixed'}"],
    ids=["through-the-cycle", "control"],
)
def test_input_the_parent_passes_its_child_reaches_the_parent_filter_django_applies(tmp_path: Path, context: str) -> None:
    assert exploitable(tmp_path, context) == [(5, "b.html", "1")]


def described(root: Path) -> dict[str, list[tuple[str, str, int, int, str, tuple[str, ...], tuple[str, ...]]]]:
    """Each template's filters, in order: the function, the file and the line and column it
    is applied at, the template applying it, and the names reaching its value and argument."""

    return {
        name: [
            (
                str(f.symbol),
                Path(str(f.location.source_id)).name,
                f.location.start_line,
                f.location.start_column,
                f.template,
                f.value,
                f.argument,
            )
            for f in found
        ]
        for name, found in project_templates(root).filters.items()
    }


def test_a_template_including_itself_with_other_bindings_reaches_them(tmp_path: Path) -> None:
    # Django applies upper to v, then, one level down, to n0; the condition ends there.
    # In a cycle, the names reaching a filter application are joined into one call.
    root = write(tmp_path, {"app/templates/t.html": "{{ v|upper }}{% if go %}{% include 't.html' with v=n0 go='' %}{% endif %}\n"})

    assert described(root) == {"t.html": [(f"{FILTERS}.upper", "t.html", 1, 6, "t.html", ("n0", "v"), ())]}


def test_a_recursive_tree_reaches_the_children_at_every_level(tmp_path: Path) -> None:
    # Django applies upper to node.name, then to the name of each node of node.children.
    node = "{{ node.name|upper }}{% for child in node.children %}{% include 'node.html' with node=child %}{% endfor %}\n"
    root = write(tmp_path, {"app/templates/node.html": node})

    assert described(root) == {"node.html": [(f"{FILTERS}.upper", "node.html", 1, 14, "node.html", ("node.children", "node.name"), ())]}


COUNT_FILTERS = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from coretrace_python.taint.templates import project_templates\n"
    "print(json.dumps({name: len(found) for name, found in project_templates(Path(sys.argv[1])).filters.items()}))\n"
)


def counted(root: Path) -> dict[str, int]:
    """Each template's number of filters, counted in a subprocess bounded in time."""

    try:
        completed = subprocess.run(
            [sys.executable, "-c", COUNT_FILTERS, str(root)], capture_output=True, text=True, check=False, timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"collecting the filters did not end within {TIMEOUT} s")
    assert completed.returncode == 0, completed.stderr
    counts: dict[str, int] = json.loads(completed.stdout)
    return counts


def test_a_cycle_through_includes_doubled_at_every_level_is_collected_in_linear_time(tmp_path: Path) -> None:
    # Cut at each template on the way, every walk inside the cycle is cut, and each is
    # walked again on every path: 20 levels took a minute.
    templates = {"app/templates/level0.html": "{{ name|upper }}{% if more %}{% include 'level60.html' %}{% endif %}"}
    for level in range(1, 61):
        templates[f"app/templates/level{level}.html"] = f"{{% include 'level{level - 1}.html' %}}" * 2

    assert counted(write(tmp_path, templates)) == {f"level{level}.html": 1 for level in range(61)}


def test_templates_each_including_every_other_are_collected_in_polynomial_time(tmp_path: Path) -> None:
    # Each template reaches the filter of every other one, through any of their orders.
    names = [f"t{index}.html" for index in range(40)]
    templates = {
        f"app/templates/{name}": "{{ v|upper }}" + "".join(f"{{% if go %}}{{% include '{other}' %}}{{% endif %}}" for other in names if other != name)
        for name in names
    }

    assert counted(write(tmp_path, templates)) == {name: 40 for name in names}


def test_bindings_permuted_around_a_cycle_are_joined_at_each_filter(tmp_path: Path) -> None:
    # Each combination of the 24 names would be its own fact; joined at each filter
    # application, the chain's 7 filters are 7 calls.
    rotated = " ".join(f"v{index}=v{(index + 1) % 24}" for index in range(24))
    template = (
        "{{ v0|default:v1|default:v2|default:v3|default:v4|default:v5|default:v6|upper }}\n"
        "{% if go %}\n"
        "{% include 't.html' with " + rotated + " go='' %}\n"
        "{% include 't.html' with v0=v1 v1=v0 go='' %}\n"
        "{% endif %}\n"
    )

    assert counted(write(tmp_path, {"app/templates/t.html": template})) == {"t.html": 7}


NAMES = [f"t{index}.html" for index in range(4)]


def generated(rng: random.Random, fresh: Iterator[str], depth: int = 0) -> str:
    """Markup applying filters, including other templates, inside blocks of two names and
    outside them, each include binding the variable to a name of its own."""

    pieces: list[Callable[[], str]] = [
        lambda: "{{ v|upper }}",
        lambda: "{{ v|striptags }}",
        lambda: "{% include '" + rng.choice(NAMES) + "' %}",
        lambda: "{% include '" + rng.choice(NAMES) + "' with v=" + next(fresh) + " %}",
    ]
    if depth < 2:
        block = rng.choice(["body", "side"])
        pieces.append(lambda: "{% block " + block + " %}" + generated(rng, fresh, depth + 1) + "{% endblock %}")
    return "".join(rng.choice(pieces)() for _ in range(rng.randint(1, 3)))


def scopes(root: Path) -> tuple[dict[str, list[Path]], dict[Path, Any]]:
    """The template files of each name under ``root``, and what each file reads as."""

    found = {path: tuple(templates._names(path.relative_to(root).parts)) for path in discover_files(root)}
    libraries = templates._libraries(found)
    paths = sorted(path for path, names in found.items() if names)
    files: dict[str, list[Path]] = {}
    for path in paths:
        for name in found[path]:
            files.setdefault(name, []).append(path)
    read = {path: templates._read_scopes(text, SourceId(str(path)), libraries) for path in paths if (text := templates._text(path))}
    return files, read


def joined(found: Iterable[tuple[Any, ...]]) -> dict[tuple[Any, ...], tuple[frozenset[str], frozenset[str]]]:
    """The names reaching the value and the argument of each filter application, joined."""

    names: dict[tuple[Any, ...], tuple[frozenset[str], frozenset[str]]] = {}
    for symbol, span, where, value, argument in found:
        values, arguments = names.get((symbol, span, where), (frozenset(), frozenset()))
        names[symbol, span, where] = values | value, arguments | argument
    return names


def test_the_filters_are_a_fixpoint_whatever_order_the_templates_are_computed_in(tmp_path: Path) -> None:
    """On generated projects of four templates extending and including one another, cycles
    among them: what each template, with the blocks overridden, reaches is what it applies
    with what its references reach mapped through them, exactly outside cycles and joined
    by filter application in them, and the lists are the same, order included, whatever
    order the templates are inserted in."""

    rng = random.Random(284)
    for index in range(500):
        fresh = (f"n{number}" for number in itertools.count())
        texts = {}
        for name in NAMES:
            extends = "{% extends '" + rng.choice(NAMES) + "' %}" if rng.random() < 0.5 else ""
            texts[f"app/templates/{name}"] = extends + generated(rng, fresh) + "\n"
        files, read = scopes(write(tmp_path / str(index), texts))
        renders = templates._renders(files, read)
        settled = templates._settled(files, read)
        cyclic = {
            pair
            for component in templates._components(renders)
            for pair in component
            if len(component) > 1 or any(below == pair for below, _ in renders[pair].references)
        }

        for pair, render in renders.items():
            reached = [fact for below, reference in render.references for fact in templates._mapped(settled[below], reference)]
            if pair in cyclic:
                assert len(settled[pair]) == len(joined(settled[pair])), texts
                assert joined(settled[pair]) == joined([*render.applied, *reached]), texts
            else:
                assert set(settled[pair]) == {*render.applied, *reached}, texts
        for shuffle in range(3):
            names = list(files)
            random.Random(shuffle).shuffle(names)
            assert templates._settled({name: files[name] for name in names}, read) == settled, texts
