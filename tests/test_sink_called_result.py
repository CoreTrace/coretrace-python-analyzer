"""The contract of ``Sink.requires_called_result`` (#240, part 2): the kinds of a sink that
apply only when the call's result is itself called.

A kind requires the called result only when every declaration carrying it does: merging
never weakens an unconditional kind, whatever the order, and another kind added to the
same sink, such as an advisory's, does not make a conditional one unconditional. A
record of the call applies the unconditional kinds to the selection and the conditional
ones to each invocation of its result.
"""

from __future__ import annotations

import pytest

from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import ModelTable, Sink, TaintKind

GETATTR = SymbolId("python.builtins.getattr")
CODE, ADVISORY, PATH = TaintKind.CODE, TaintKind.ADVISORY, TaintKind.PATH
NONE = TaintKind.NONE


def sink(kinds: TaintKind, requires: TaintKind = NONE) -> Sink:
    return Sink(GETATTR, kinds, requires_called_result=requires)


@pytest.mark.parametrize(
    ("first", "second", "kinds", "requires"),
    [
        # Both conditional: conditional.
        (sink(CODE, CODE), sink(CODE, CODE), CODE, CODE),
        # One unconditional declaration of the kind: unconditional.
        (sink(CODE, CODE), sink(CODE), CODE, NONE),
        # Another kind, unconditional, leaves the conditional one as it was.
        (sink(CODE, CODE), sink(ADVISORY), CODE | ADVISORY, CODE),
        # Kinds of each side keep their own requirement.
        (sink(CODE | PATH, CODE), sink(PATH, PATH), CODE | PATH, CODE),
    ],
)
def test_a_kind_requires_the_called_result_only_when_every_declaration_does(
    first: Sink, second: Sink, kinds: TaintKind, requires: TaintKind
) -> None:
    for merged in (first.merged(second), second.merged(first)):
        assert (merged.kinds, merged.requires_called_result) == (kinds, requires)


def test_an_advisory_sink_added_to_the_table_keeps_the_conditional_kind() -> None:
    table = ModelTable((), (sink(CODE, CODE),), ()).extended(Sink(GETATTR, ADVISORY))
    merged = table.sink(GETATTR)

    assert merged is not None
    assert merged.requires_called_result == CODE


def test_a_record_applies_the_kinds_its_record_calls_for() -> None:
    both = Sink(GETATTR, CODE | ADVISORY, ((CODE, (1,)),), selects=True, requires_called_result=CODE)

    selection = both.applying(invoked=False)
    invocation = both.applying(invoked=True)

    assert selection is not None and selection.kinds == ADVISORY
    assert invocation is not None and invocation.kinds == CODE
    # What else the sink says is kept.
    assert invocation.selects and invocation.kinds_at(1) == CODE and invocation.kinds_at(0) == NONE
    assert sink(CODE, CODE).applying(invoked=False) is None
    assert sink(CODE).applying(invoked=True) is None
