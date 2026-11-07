"""The representative copy may omit only state that merge immediately rebuilds."""
import itertools
import json
from unittest.mock import patch

from pydantic import ConfigDict, Field, PrivateAttr
import pytest

from attackmap.models import Signal, SignalConflict, SignalOrigin
from attackmap.signal_provenance import _copy_merge_representative, merge_normalized_signals


class ExtendedSignal(Signal):
    model_config = ConfigDict(extra="allow")
    nested: dict[str, list[str]] = Field(default_factory=lambda: {"values": ["kept"]})
    _scratch: list = PrivateAttr(default_factory=lambda: [{"values": ["private"]}])


def _signals(case):
    if case == 0:
        return [Signal(kind="route", label="GET /a", file="app.py")]
    if case == 1:
        return [Signal(kind="route", label="GET /a", file="app.py", properties={}, evidence_text=None)]
    if case == 2:
        return [Signal(kind="route", label="POST /x", file="app.py", line=line,
                       properties={"auth": auth, "opaque": "retained"}, source_role=role,
                       classification_basis=basis, evidence_kind=kind,
                       origins=[SignalOrigin(analyzer="producer", analyzer_version=version,
                                             metadata_status=status, file="app.py", line=line,
                                             properties={"opaque": "kept"})],
                       conflicts=[SignalConflict(field="auth", values=["optional", "required", "required"])])
                for line, auth, role, basis, kind, version, status in [
                    (10, "required", "production", "detector_owned", "static_extraction", "0.1.0", "known"),
                    (20, "optional", "unknown", "unknown", "unknown", None, "legacy_unknown")]]
    if case == 3:
        shared = SignalOrigin(analyzer="same", properties={"shared": "value"})
        return [Signal(kind="auth", label=label, file="app.py", origins=[shared])
                for label in ("first", "second")]
    if case == 4:
        return [ExtendedSignal(kind="framework", label="extended", file="app.py",
                               future={"values": ["extra"]}, origins=[SignalOrigin(analyzer="extended")])]
    if case == 5:
        return [Signal(kind="service", label="svc", file="", confidence=0.0,
                       properties={"unknown-key": "unknown-value"},
                       origins=[SignalOrigin(), SignalOrigin(analyzer=None, analyzer_version=None, properties={})])]
    if case == 6:
        return [Signal(kind="route", label="GET /a", file="app.py", line=line,
                       origins=[SignalOrigin(analyzer=analyzer, properties=properties)])
                for line, analyzer, properties in [(7, "one", {}), (9, "two", {"x": "y"})]]
    return [Signal(kind="external_call", label="https://example.invalid", file="app.py", line=2,
                   properties={"method": method}) for method in ("GET", "POST")]


def _signature(items):
    fields = [(type(s).__name__, sorted(s.model_fields_set),
               [sorted(o.model_fields_set) for o in s.origins],
               [sorted(c.model_fields_set) for c in s.conflicts],
               s.__pydantic_private__, s.__pydantic_extra__) for s in items]
    flags = [dict(zip(("exclude_unset", "exclude_defaults", "exclude_none"), bits))
             for bits in itertools.product((False, True), repeat=3)]
    return json.dumps({"fields": fields,
                       "json": [[s.model_dump_json(**flag) for s in items] for flag in flags]}, sort_keys=True)


def _mutate(items):
    for signal in items:
        signal.properties["probe"] = "changed"
        signal.confidence = .123
        for origin in signal.origins:
            origin.properties["origin-probe"] = "changed"
            origin.file = "changed.py"
        for conflict in signal.conflicts:
            conflict.values.append("conflict-probe")
        if isinstance(signal, ExtendedSignal):
            signal.nested["values"].append("changed")
            signal._scratch[0]["values"].append("changed")
            signal.model_extra["future"]["values"].append("changed")


@pytest.mark.parametrize("case", range(8))
@pytest.mark.parametrize("reverse", (False, True))
def test_merge_matches_legacy_copy_all_json_options_and_field_sets(case, reverse):
    inputs = _signals(case)
    if reverse:
        inputs.reverse()
    before = _signature(inputs)
    # The only changed operation is representative cloning; retain the old copy as oracle.
    with patch("attackmap.signal_provenance._copy_merge_representative", lambda s: s.model_copy(deep=True)):
        expected = merge_normalized_signals(inputs)
    actual = merge_normalized_signals(inputs)
    assert _signature(actual) == _signature(expected)
    assert _signature(inputs) == before
    _mutate(actual)
    assert _signature(inputs) == before
    fresh = _signals(case)
    output = merge_normalized_signals(fresh)
    snapshot = _signature(output)
    _mutate(fresh)
    assert _signature(output) == snapshot


def test_shared_input_origin_never_aliases_sibling_results():
    output = merge_normalized_signals(_signals(3))
    output[0].origins[0].properties["sibling"] = "changed"
    assert "sibling" not in output[1].origins[0].properties


@pytest.mark.parametrize("state", ("subclass", "extra", "private", "unexpected", "properties_subclass", "mutable_property"))
def test_unknown_state_uses_legacy_deepcopy_and_isolates_mutations(state):
    signal = (ExtendedSignal(kind="service", label="svc", file="app.py") if state == "subclass"
              else Signal(kind="service", label="svc", file="app.py"))
    if state == "extra":
        object.__setattr__(signal, "__pydantic_extra__", {"future": {"values": ["kept"]}})
        mutable = lambda s: s.__pydantic_extra__["future"]["values"]
    elif state == "private":
        object.__setattr__(signal, "__pydantic_private__", {"future": {"values": ["kept"]}})
        mutable = lambda s: s.__pydantic_private__["future"]["values"]
    elif state == "unexpected":
        signal.__dict__["future_mutable"] = {"values": ["kept"]}
        mutable = lambda s: s.__dict__["future_mutable"]["values"]
    elif state == "properties_subclass":
        class Properties(dict):
            pass
        signal.properties = Properties(value="kept")
        mutable = lambda s: s.properties
    elif state == "mutable_property":
        # Deliberately emulate future/unvalidated runtime state without changing the schema.
        signal.properties["future"] = ["kept"]
        mutable = lambda s: s.properties["future"]
    else:
        mutable = lambda s: s.nested["values"]
    calls = []
    original = Signal.model_copy
    def observed(self, *, update=None, deep=False):
        calls.append(deep)
        return original(self, update=update, deep=deep)
    with patch.object(Signal, "model_copy", observed):
        copied = _copy_merge_representative(signal)
    assert calls == [True]
    assert copied.model_fields_set == signal.model_fields_set
    left, right = mutable(signal), mutable(copied)
    assert left == right and left is not right
    if isinstance(right, list):
        right.append("copy-change")
        assert "copy-change" not in left
        left.append("input-change")
        assert "input-change" not in right
    else:
        right["copy-change"] = "yes"
        assert "copy-change" not in left
        left["input-change"] = "yes"
        assert "input-change" not in right
