"""Deposit-origin classification: worker vs manual vs unknown.

Fixture tests lock the classifier to the labeled captures (including the
7002 ambient non-matching decrement and both storage-delta context modes);
synthetic tests pin the fail-closed rules that no capture currently
exercises.
"""

from pathlib import Path

import pytest

from bdo_toolkit import replay_pcap
from bdo_toolkit._deposit_origin import DecrementSpec, DepositOriginTracker
from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.events import BDOEvent, Flow

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

requires_fixtures = pytest.mark.skipif(
    not FIXTURE_DIR.exists() or not any(FIXTURE_DIR.glob("*.pcapng")),
    reason="local pcap fixtures not present (private captures)",
)

# Worker deposits span BOTH storage-delta context modes (05 and 20).
WORKER_FIXTURES = [
    "worker_4607.pcapng",
    "5960_qty1_and_4015_qty1_multi.pcapng",
    "7360_hit2_qty10.pcapng",
    "7002_qty25.pcapng",
]
MANUAL_FIXTURES = [
    "1000306_qty5_unstackable_i2s.pcapng",
    "new_potato_3_tostorage.pcapng",
    "new_potato_1_1_1.pcapng",
]


def _origins(fixture):
    return [
        (event.deposit_origin, event.extra.get("deposit_origin_evidence"))
        for event in replay_pcap(FIXTURE_DIR / fixture)
        if event.event_type == "storage_delta"
    ]


@requires_fixtures
@pytest.mark.parametrize("fixture", WORKER_FIXTURES)
def test_worker_deposits_classify_as_worker(fixture):
    results = _origins(fixture)
    assert results, f"no storage_delta events decoded from {fixture}"
    for origin, evidence in results:
        assert origin == "worker"
        assert evidence == {"worker_companions": True, "matching_decrement": False}


@requires_fixtures
@pytest.mark.parametrize("fixture", MANUAL_FIXTURES)
def test_manual_deposits_classify_as_manual(fixture):
    results = _origins(fixture)
    assert results, f"no storage_delta events decoded from {fixture}"
    for origin, evidence in results:
        assert origin == "manual"
        assert evidence == {"worker_companions": False, "matching_decrement": True}


@requires_fixtures
def test_ambient_nonmatching_decrement_does_not_flip_worker_verdict():
    # 7002_qty25 has a 0x1A32 near the deposit that does NOT carry qty=25:
    # presence alone must not read as manual.
    (origin, evidence), = _origins("7002_qty25.pcapng")
    assert origin == "worker"
    assert evidence["matching_decrement"] is False


# --- synthetic fail-closed behavior ---

FLOW = FlowKey("10.0.0.1", 8889, "10.0.0.2", 50000)


def _frame(opcode, seq, timestamp=1000.0, body=b"", length=None):
    payload = bytearray(max(length or (5 + len(body)), 5 + len(body)))
    payload[0:2] = len(payload).to_bytes(2, "little")
    payload[3:5] = opcode.to_bytes(2, "little")
    payload[5 : 5 + len(body)] = body
    return BDOFrame(
        index=0,
        message=bytes(payload),
        context=PacketContext(timestamp=timestamp, flow=FLOW),
        stream_sequence=seq,
    )


def _storage_event(item_id=7002, quantity=25, seq=1000, timestamp=1000.0):
    return BDOEvent(
        event_type="storage_delta",
        timestamp=timestamp,
        flow=Flow("10.0.0.1", 8889, "10.0.0.2", 50000),
        item_id=item_id,
        quantity=quantity,
        extra={"stream_sequence": seq},
    )


def _tracker(emitted):
    return DepositOriginTracker(
        decrement_specs=(DecrementSpec(0x1A32, quantity_offset=42),),
        emit=emitted.append,
    )


def test_no_evidence_yields_unknown():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(seq=1000))
    tracker.finalize_all()
    assert emitted[0].deposit_origin == "unknown"


def test_companions_outrank_a_spurious_decrement_match():
    # Companions present AND a (possibly spurious) decrement match => worker,
    # NOT unknown. Companions have perfect separation; a quantity-only
    # decrement match collides for small quantities and must not veto them.
    # Evidence is still recorded truthfully for auditability.
    emitted = []
    tracker = _tracker(emitted)
    decrement = bytearray(52)
    decrement[0:2] = (52).to_bytes(2, "little")
    decrement[3:5] = (0x1A32).to_bytes(2, "little")
    decrement[42:46] = (1).to_bytes(4, "little")  # qty=1: the colliding value
    tracker.observe_frame(
        BDOFrame(
            index=0,
            message=bytes(decrement),
            context=PacketContext(timestamp=999.0, flow=FLOW),
            stream_sequence=900,
        )
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(quantity=1, seq=1000))
    tracker.observe_frame(_frame(0x1558, seq=1100))
    tracker.observe_frame(_frame(0x1168, seq=1200))
    tracker.finalize_all()
    assert emitted[0].deposit_origin == "worker"
    assert emitted[0].extra["deposit_origin_evidence"] == {
        "worker_companions": True,
        "matching_decrement": True,
    }


def test_multi_record_worker_batch_agrees_across_records():
    # The exact reported bug: two records of ONE worker batch frame, the qty=1
    # record spuriously matching a decrement while the qty=25 record does not.
    # Both must classify worker; companions are shared by the whole frame.
    emitted = []
    tracker = _tracker(emitted)
    decrement = bytearray(60)
    decrement[0:2] = (60).to_bytes(2, "little")
    decrement[3:5] = (0x1A32).to_bytes(2, "little")
    decrement[42:46] = (1).to_bytes(4, "little")
    tracker.observe_frame(
        BDOFrame(
            index=0,
            message=bytes(decrement),
            context=PacketContext(timestamp=999.0, flow=FLOW),
            stream_sequence=900,
        )
    )
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    # Both records share the frame's stream_sequence.
    tracker.register(_storage_event(item_id=4409, quantity=1, seq=1000))
    tracker.register(_storage_event(item_id=4004, quantity=25, seq=1000))
    tracker.observe_frame(_frame(0x1558, seq=1100))
    tracker.observe_frame(_frame(0x1168, seq=1200))
    tracker.finalize_all()
    origins = [e.deposit_origin for e in emitted]
    assert origins == ["worker", "worker"]


def test_companions_already_in_segment_finalize_immediately():
    # The frame tap runs ahead of the event decoder, so companions in the
    # same TCP segment are visible at registration time.
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.observe_frame(_frame(0x1558, seq=1100))
    tracker.observe_frame(_frame(0x1168, seq=1200))
    tracker.register(_storage_event(seq=1000))
    assert emitted and emitted[0].deposit_origin == "worker"


def test_stale_pending_deposit_flushes_as_unknown():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000, timestamp=1000.0))
    tracker.register(_storage_event(seq=1000, timestamp=1000.0))
    assert not emitted
    tracker.flush_stale(now=1005.0)
    assert emitted[0].deposit_origin == "unknown"


def test_lookahead_window_expires_after_unrelated_frames():
    emitted = []
    tracker = _tracker(emitted)
    tracker.observe_frame(_frame(0x0E6A, seq=1000))
    tracker.register(_storage_event(seq=1000))
    for i in range(4):
        tracker.observe_frame(_frame(0x1CAE, seq=1100 + i))
    assert emitted and emitted[0].deposit_origin == "unknown"


@requires_fixtures
def test_format_human_shows_deposit_origin():
    events = list(replay_pcap(FIXTURE_DIR / "worker_4607.pcapng"))
    line = events[0].format_human()
    assert "deposit_origin=worker" in line


@requires_fixtures
def test_deposit_origins_filter_is_first_class():
    # The dev-facing worker-tracker one-liner: filter at the API, applied
    # AFTER classification so the verdict is already on the event.
    manual = FIXTURE_DIR / "1000306_qty5_unstackable_i2s.pcapng"
    worker = FIXTURE_DIR / "worker_4607.pcapng"

    assert list(replay_pcap(manual, deposit_origins={"worker"})) == []
    assert len(list(replay_pcap(manual, deposit_origins={"manual"}))) == 5

    events = list(replay_pcap(worker, deposit_origins={"worker"}))
    assert [(e.item_id, e.deposit_origin) for e in events] == [(4607, "worker")]


def test_deposit_origin_defaults_to_none_off_storage_deltas():
    from bdo_toolkit.events import BDOEvent, Flow

    event = BDOEvent(
        event_type="item_received",
        timestamp=1000.0,
        flow=Flow("1.1.1.1", 8889, "2.2.2.2", 50000),
        item_id=7003,
        quantity=1,
    )
    assert event.deposit_origin is None
    assert "deposit_origin" not in event.to_dict()

    from bdo_toolkit.filters import EventFilter

    f = EventFilter.from_values(deposit_origins={"worker"})
    assert not f.allows(event)  # None never matches a set filter
