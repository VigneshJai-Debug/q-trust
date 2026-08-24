"""Property-based tests for the evidence ledger hash chain."""
from __future__ import annotations

import tempfile

from hypothesis import given, settings
from hypothesis import strategies as st

from qtrust_inspector.evidence import EvidenceLedger

scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10000, max_value=10000),
    st.text(
        alphabet=st.characters(blacklist_characters='"\\', blacklist_categories=("Cs",)),
        max_size=12,
    ),
)

cboms = st.fixed_dictionaries({
    "schema_version": st.just("qtrust.cbom.v1"),
    "target": st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-", min_size=1, max_size=15),
    "assets": st.lists(
        st.dictionaries(
            st.text(alphabet="abcdefghij_", min_size=1, max_size=8), scalars, max_size=4
        ),
        max_size=4,
    ),
})

cbom_lists = st.lists(cboms, min_size=1, max_size=20)


def _build(cbom_list) -> EvidenceLedger:
    ledger = EvidenceLedger(batch_id="prop-batch")
    for cbom in cbom_list:
        ledger.append(cbom)
    return ledger


@settings(max_examples=50)
@given(cbom_list=cbom_lists)
def test_random_chain_appends_verify(cbom_list):
    ledger = _build(cbom_list)
    assert ledger.verify_chain() is True
    assert len(ledger.entries) == len(cbom_list)
    assert [e.index for e in ledger.entries] == list(range(len(cbom_list)))
    assert ledger.entries[0].prev_hash == "0" * 64


@settings(max_examples=50)
@given(data=st.data())
def test_random_middle_entry_tamper_detected(data):
    cbom_list = data.draw(st.lists(cboms, min_size=2, max_size=20))
    ledger = _build(cbom_list)
    position = data.draw(st.integers(min_value=0, max_value=len(cbom_list) - 1))
    field = data.draw(st.sampled_from(["cbom_hash", "prev_hash", "timestamp", "batch_id", "index"]))

    entry = ledger.entries[position]
    setattr(entry, field, "tampered-value")

    assert ledger.verify_chain() is False


@settings(max_examples=50)
@given(data=st.data())
def test_removing_head_or_middle_entry_breaks_chain(data):
    cbom_list = data.draw(st.lists(cboms, min_size=2, max_size=20))
    ledger = _build(cbom_list)
    removed = data.draw(st.integers(min_value=0, max_value=len(cbom_list) - 2))

    survivors = [
        entry.model_dump()
        for i, entry in enumerate(ledger.entries)
        if i != removed
    ]
    truncated = EvidenceLedger.from_dict({"batch_id": ledger.batch_id, "entries": survivors})

    assert truncated.verify_chain() is False


@settings(max_examples=30)
@given(data=st.data())
def test_prefix_truncation_stays_internally_valid(data):
    cbom_list = data.draw(st.lists(cboms, min_size=2, max_size=20))
    ledger = _build(cbom_list)
    keep = data.draw(st.integers(min_value=1, max_value=len(cbom_list) - 1))

    prefix = [entry.model_dump() for entry in ledger.entries[:keep]]
    truncated = EvidenceLedger.from_dict({"batch_id": ledger.batch_id, "entries": prefix})

    assert truncated.verify_chain() is True
    assert len(truncated.entries) == keep


@settings(max_examples=40)
@given(cbom_list=cbom_lists, metadata=st.dictionaries(st.text(max_size=6), scalars, max_size=3))
def test_save_load_roundtrip_preserves_chain(cbom_list, metadata):
    ledger = EvidenceLedger(batch_id="prop-batch")
    for cbom in cbom_list:
        ledger.append(cbom, metadata=metadata or None)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    ledger.save(path)
    loaded = EvidenceLedger.load(path)

    assert loaded.batch_id == "prop-batch"
    assert [e.model_dump() for e in loaded.entries] == [e.model_dump() for e in ledger.entries]
    assert loaded.verify_chain() is True
