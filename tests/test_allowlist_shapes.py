"""Acceptance tests for issue #239: which allowlists prove a value, through the bundled
command-injection rule.

A membership test proves the value when the collection is constant and stable: a tuple,
list, set or dict literal at the point of use, ``frozenset``/``set``/``tuple``/``list`` of
such a literal, the keys of a dict literal, or a module-level tuple or ``frozenset`` of
constants bound once and never rebound. A lookup with an input key in a dict literal of
constants gives one of its constants. A module-level list, set or dict is mutable: its
stability is not shown, so it keeps today's verdict (a hotspot for a membership test, a
vulnerability for a lookup), as does any collection with an element that is not a
constant.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from coretrace_python.cli import main

APP = """\
import os

from flask import Flask, request

app = Flask(__name__)

ALLOWED_TUPLE = ("ls", "date")
ALLOWED_FROZENSET = frozenset({"ls", "date"})
ALLOWED_SET = {"ls", "date"}
ALLOWED_LIST = ["ls", "date"]
COMMANDS = {"list": "ls", "where": "date"}

MUTATED = ["ls", "date"]
REBOUND = ("ls", "date")
MIXED = ("ls", os.environ.get("EXTRA_COMMAND", "date"))
FROZEN_MIXED = frozenset({"ls", os.environ.get("EXTRA_COMMAND", "date")})
EXTENDED = ("ls",)
EXTENDED += ("date",)


def extend(extra):
    MUTATED.append(extra)


def rebind(extra):
    global REBOUND
    REBOUND = (extra,)


@app.route("/literal-tuple")
def literal_tuple():
    cmd = request.args["c"]
    if cmd in ("ls", "date"):
        os.system(cmd)


@app.route("/literal-list")
def literal_list():
    cmd = request.args["c"]
    if cmd in ["ls", "date"]:
        os.system(cmd)


@app.route("/literal-set")
def literal_set():
    cmd = request.args["c"]
    if cmd in {"ls", "date"}:
        os.system(cmd)


@app.route("/literal-frozenset")
def literal_frozenset():
    cmd = request.args["c"]
    if cmd in frozenset(("ls", "date")):
        os.system(cmd)


@app.route("/literal-frozenset-of-set")
def literal_frozenset_of_set():
    cmd = request.args["c"]
    if cmd in frozenset({"ls", "date"}):
        os.system(cmd)


@app.route("/literal-dict-keys")
def literal_dict_keys():
    cmd = request.args["c"]
    if cmd in {"ls": "list", "date": "where"}:
        os.system(cmd)


@app.route("/literal-dict-keys-method")
def literal_dict_keys_method():
    cmd = request.args["c"]
    if cmd in {"ls": "list", "date": "where"}.keys():
        os.system(cmd)


@app.route("/literal-dict-lookup")
def literal_dict_lookup():
    os.system({"list": "ls", "where": "date"}[request.args["c"]])


@app.route("/literal-dict-get-default")
def literal_dict_get_default():
    os.system({"list": "ls", "where": "date"}.get(request.args["c"], "true"))


@app.route("/module-tuple")
def module_tuple():
    cmd = request.args["c"]
    if cmd in ALLOWED_TUPLE:
        os.system(cmd)


@app.route("/module-frozenset")
def module_frozenset():
    cmd = request.args["c"]
    if cmd in ALLOWED_FROZENSET:
        os.system(cmd)


@app.route("/unpacked-element")
def unpacked_element():
    cmd = request.args["c"]
    extra = request.args["e"].split(",")
    if cmd in ("ls", *extra):
        os.system(cmd)


@app.route("/non-constant-element")
def non_constant_element():
    cmd = request.args["c"]
    if cmd in ("ls", request.args["extra"]):
        os.system(cmd)


@app.route("/module-tuple-mixed")
def module_tuple_mixed():
    cmd = request.args["c"]
    if cmd in MIXED:
        os.system(cmd)


@app.route("/module-frozenset-mixed")
def module_frozenset_mixed():
    cmd = request.args["c"]
    if cmd in FROZEN_MIXED:
        os.system(cmd)


@app.route("/module-tuple-extended")
def module_tuple_extended():
    cmd = request.args["c"]
    if cmd in EXTENDED:
        os.system(cmd)


@app.route("/rebound-tuple")
def rebound_tuple():
    cmd = request.args["c"]
    if cmd in REBOUND:
        os.system(cmd)


@app.route("/module-set")
def module_set():
    cmd = request.args["c"]
    if cmd in ALLOWED_SET:
        os.system(cmd)


@app.route("/module-list")
def module_list():
    cmd = request.args["c"]
    if cmd in ALLOWED_LIST:
        os.system(cmd)


@app.route("/mutated-list")
def mutated_list():
    cmd = request.args["c"]
    if cmd in MUTATED:
        os.system(cmd)


@app.route("/dict-keys")
def dict_keys():
    cmd = request.args["c"]
    if cmd in COMMANDS:
        os.system(cmd)


@app.route("/dict-keys-method")
def dict_keys_method():
    cmd = request.args["c"]
    if cmd in COMMANDS.keys():
        os.system(cmd)


@app.route("/dict-lookup")
def dict_lookup():
    os.system(COMMANDS[request.args["c"]])


@app.route("/dict-get-default")
def dict_get_default():
    os.system(COMMANDS.get(request.args["c"], "true"))


@app.route("/literal-dict-non-constant-value")
def literal_dict_non_constant_value():
    os.system({"list": "ls", "custom": request.args["x"]}[request.args["c"]])


@app.route("/literal-dict-get-tainted-default")
def literal_dict_get_tainted_default():
    os.system({"list": "ls"}.get(request.args["c"], request.args["fallback"]))

def register(values):
    values.append(os.environ.get("EXTRA_COMMAND", "date"))


@app.route("/local-list")
def local_list():
    cmd = request.args["c"]
    allowed = ["ls", "date"]
    if cmd in allowed:
        os.system(cmd)


@app.route("/local-dict-keys-read")
def local_dict_keys_read():
    cmd = request.args["c"]
    commands = {"ls": "list", "date": "when"}
    print(commands.get("ls"))
    if cmd in commands.keys():
        os.system(cmd)


@app.route("/local-list-appended")
def local_list_appended():
    cmd = request.args["c"]
    allowed = ["ls"]
    allowed.append(request.args["extra"])
    if cmd in allowed:
        os.system(cmd)


@app.route("/local-set-added")
def local_set_added():
    cmd = request.args["c"]
    allowed = {"ls"}
    allowed.add(request.args["extra"])
    if cmd in allowed:
        os.system(cmd)


@app.route("/local-list-passed")
def local_list_passed():
    cmd = request.args["c"]
    allowed = ["ls"]
    register(allowed)
    if cmd in allowed:
        os.system(cmd)


@app.route("/local-dict-key-written")
def local_dict_key_written():
    cmd = request.args["c"]
    commands = {"ls": "list"}
    commands[request.args["k"]] = "custom"
    if cmd in commands:
        os.system(cmd)


@app.route("/local-dict-value-written")
def local_dict_value_written():
    commands = {"list": "ls"}
    commands["custom"] = request.args["x"]
    os.system(commands[request.args["c"]])
"""

NOT_REPORTED = None
HOTSPOT = ("hotspot", "medium")
VULNERABILITY = ("vulnerability", "high")

EXPECTED = {
    # Constant and stable: refuted, or no taint left.
    "literal_tuple": NOT_REPORTED,
    "literal_list": NOT_REPORTED,
    "literal_set": NOT_REPORTED,
    "literal_frozenset": NOT_REPORTED,
    "literal_frozenset_of_set": NOT_REPORTED,
    "literal_dict_keys": NOT_REPORTED,
    "literal_dict_keys_method": NOT_REPORTED,
    "literal_dict_lookup": NOT_REPORTED,
    "literal_dict_get_default": NOT_REPORTED,
    "module_tuple": NOT_REPORTED,
    "module_frozenset": NOT_REPORTED,
    # An element that is not a constant.
    "unpacked_element": HOTSPOT,
    "non_constant_element": HOTSPOT,
    "module_tuple_mixed": HOTSPOT,
    "module_frozenset_mixed": HOTSPOT,
    # Rebound in the module body or by a ``global`` assignment.
    "module_tuple_extended": HOTSPOT,
    "rebound_tuple": HOTSPOT,
    # Mutable module-level collections: stability not shown, today's verdict kept.
    "module_set": HOTSPOT,
    "module_list": HOTSPOT,
    "mutated_list": HOTSPOT,
    "dict_keys": HOTSPOT,
    "dict_keys_method": HOTSPOT,
    "dict_lookup": VULNERABILITY,
    "dict_get_default": VULNERABILITY,
    # A display of the function that is only read.
    "local_list": NOT_REPORTED,
    "local_dict_keys_read": NOT_REPORTED,
    # A display mutated, or passed on, before the test.
    "local_list_appended": HOTSPOT,
    "local_set_added": HOTSPOT,
    "local_list_passed": HOTSPOT,
    "local_dict_key_written": HOTSPOT,
    # A lookup whose result may be input.
    "local_dict_value_written": VULNERABILITY,
    "literal_dict_non_constant_value": VULNERABILITY,
    "literal_dict_get_tainted_default": VULNERABILITY,
}


@pytest.fixture(scope="module")
def verdicts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[str, str]]:
    root = tmp_path_factory.mktemp("allowlists")
    (root / "app.py").write_text(APP, encoding="utf-8")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["--check", str(root), "--format", "json"])
    found: dict[str, tuple[str, str]] = {}
    for finding in json.loads(out.getvalue())["findings"]:
        if finding["rule_id"] != "command-injection":
            continue
        assert finding["function"] not in found, finding
        found[finding["function"]] = (finding["metadata"]["verdict"], finding["confidence"])
    return found


@pytest.mark.parametrize("route", sorted(EXPECTED))
def test_allowlist_shape_verdict(verdicts: dict[str, tuple[str, str]], route: str) -> None:
    assert verdicts.get(route) == EXPECTED[route]


def test_every_reported_route_is_expected(verdicts: dict[str, tuple[str, str]]) -> None:
    assert set(verdicts) <= set(EXPECTED)
