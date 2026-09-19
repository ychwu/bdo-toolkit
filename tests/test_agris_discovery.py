"""Synthetic regressions for balance-only, cap-constrained Agris inference."""

from collections.abc import Iterable

import pytest

from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.agris._discovery import AgrisTracker
from bdo_toolkit.agris.models import AgrisBalance, AgrisDetectionError, AgrisDiscoveryOptions


FLOW = FlowKey("192.0.2.1", 8889, "192.0.2.2", 40000)
OTHER_FLOW = FlowKey("192.0.2.3", 8889, "192.0.2.2", 40001)
VALUES = (98600, 98560, 98480, 98440, 98400)


def frame(
    points: int,
    *,
    index: int = 0,
    timestamp: float | None = None,
    opcode: int = 0x3456,
    length: int = 64,
    remaining_offset: int = 11,
    maximum_offset: int | None = 33,
    maximum: int = 100000,
    duplicate_remaining: int | None = None,
    duplicate_maximum: int | None = None,
    flow: FlowKey = FLOW,
    generation: int = 1,
    flag: int = 0,
) -> BDOFrame:
    message = bytearray([0xAB] * length)
    message[:2] = length.to_bytes(2, "little")
    message[2] = flag
    message[3:5] = opcode.to_bytes(2, "little")
    message[remaining_offset : remaining_offset + 4] = points.to_bytes(4, "little")
    if maximum_offset is not None:
        message[maximum_offset : maximum_offset + 4] = maximum.to_bytes(4, "little")
    if duplicate_remaining is not None:
        message[duplicate_remaining : duplicate_remaining + 4] = points.to_bytes(4, "little")
    if duplicate_maximum is not None:
        message[duplicate_maximum : duplicate_maximum + 4] = maximum.to_bytes(4, "little")
    return BDOFrame(
        index,
        bytes(message),
        PacketContext(float(index) if timestamp is None else timestamp, flow, flow_generation=generation),
        index * length,
    )


def tracker(**kwargs: object) -> AgrisTracker:
    return AgrisTracker(expected_maximum_points=100000, options=AgrisDiscoveryOptions(settle_seconds=0), **kwargs)


def feed(target: AgrisTracker, values: Iterable[int] = VALUES, *, start: int = 0, **kwargs: object) -> None:
    for index, value in enumerate(values, start):
        target.observe(frame(value, index=index, **kwargs))


@pytest.mark.parametrize(
    "geometry",
    [
        {"opcode": 0x1337, "length": 40, "remaining_offset": 9, "maximum_offset": 13},
        {"opcode": 0x1746, "length": 37, "remaining_offset": 33, "maximum_offset": 12},
        {"opcode": 0x9876, "length": 103, "remaining_offset": 57, "maximum_offset": 8},
        {"opcode": 1, "length": 28, "remaining_offset": 5, "maximum_offset": 24},
    ],
)
def test_discovers_changed_opcode_length_and_unaligned_offsets(geometry):
    events = []
    target = tracker(on_balance=events.append)
    feed(target, **geometry)
    status = target.snapshot()
    assert status.status == "tracking"
    assert status.balance is not None
    assert status.balance.remaining_points == VALUES[-1]
    assert status.balance.maximum_points == 100000
    assert status.balance.confidence == "inferred"
    assert status.balance.observed_at == 4
    assert len(events) == 1  # Never replay inferred startup history as events.
    assert status.candidates[0].opcode == geometry["opcode"]
    assert status.candidates[0].message_length == geometry["length"]
    assert status.candidates[0].remaining_offset == geometry["remaining_offset"]
    assert status.candidates[0].maximum_offset == geometry["maximum_offset"]


def test_first_balance_and_repeated_balances_are_not_discovery():
    target = tracker()
    assert target.snapshot().balance is None
    feed(target, [99960] * 20)
    assert target.snapshot().status == "searching"
    assert target.snapshot().balance is None
    feed(target, [99959, 99843, 98204, 98000], start=20)
    assert target.snapshot().status == "tracking"


def test_settling_uses_observation_time_but_balance_keeps_packet_timestamp():
    events = []
    target = AgrisTracker(expected_maximum_points=100000, on_balance=events.append)
    feed(target)
    assert target.snapshot().status == "settling"
    assert target.snapshot().balance is None
    target.refresh(6.9)
    assert not events
    status = target.refresh(7)
    assert status.status == "tracking"
    assert status.balance.observed_at == 4
    assert events == [status.balance]
    assert target.refresh(100).balance.observed_at == 4
    for _ in range(5):
        assert target.snapshot() == target.snapshot()
    assert len(events) == 1


def test_only_latest_balance_is_emitted_when_discovery_settles():
    events = []
    target = AgrisTracker(expected_maximum_points=100000, on_balance=events.append)
    feed(target)
    target.observe(frame(98000, index=5))
    target.observe(frame(97980, index=6))
    assert not events
    target.refresh(7)
    assert [event.remaining_points for event in events] == [97980]


def test_equal_increase_and_zero_are_valid_actual_updates_after_selection():
    events: list[AgrisBalance] = []
    target = tracker(on_balance=events.append)
    feed(target)
    feed(target, [98400, 98400, 99999, 100000, 0], start=5)
    assert [event.remaining_points for event in events] == [98400, 98400, 98400, 99999, 100000, 0]
    assert target.snapshot().status == "tracking"
    assert target.snapshot().balance.remaining_points == 0
    # Pure reads and clock advancement never synthesize extra balance events.
    target.refresh(100)
    assert len(events) == 6


def test_increase_before_selection_permanently_rejects_that_family_column():
    target = tracker()
    feed(target, [99000, 98999, 99001, 98800, 98700, 98600, 98500, 98400])
    assert target.snapshot().status == "searching"


@pytest.mark.parametrize("maximum", [20, 60000, 160000])
def test_explicit_non_default_caps_are_used_for_discovery(maximum):
    target = AgrisTracker(expected_maximum_points=maximum, options=AgrisDiscoveryOptions(settle_seconds=0))
    feed(target, range(maximum - 1, maximum - 6, -1), maximum=maximum)
    assert target.snapshot().status == "tracking"
    assert target.snapshot().balance.maximum_points == maximum


@pytest.mark.parametrize("configured", [1, 50000, 99999, 100001, 200000])
def test_wrong_cap_never_falls_back_to_one_hundred_thousand(configured):
    target = AgrisTracker(expected_maximum_points=configured, options=AgrisDiscoveryOptions(settle_seconds=0))
    feed(target)
    assert target.snapshot().status == "searching"
    assert target.snapshot().balance is None


@pytest.mark.parametrize("duplicates", [{"duplicate_remaining": 48}, {"duplicate_maximum": 48}])
def test_multiple_columns_or_caps_are_ambiguous(duplicates):
    target = tracker()
    feed(target, **duplicates)
    assert target.snapshot().status == "ambiguous"
    assert len(target.snapshot().candidates) == 2
    assert target.snapshot().balance is None


def test_late_competitor_suppresses_events_and_requires_resettling():
    events = []
    target = AgrisTracker(expected_maximum_points=100000, on_balance=events.append)
    feed(target)
    target.refresh(7)
    assert len(events) == 1
    feed(target, start=8, flow=OTHER_FLOW)
    assert target.snapshot().status == "ambiguous"
    assert target.snapshot().balance is None
    # Direct validation stays attached, but even valid increases emit nothing.
    target.observe(frame(99999, index=13))
    assert len(events) == 1
    target.close_flow(OTHER_FLOW)
    assert target.snapshot().status == "settling"
    target.refresh(15.9)
    assert len(events) == 1
    target.refresh(16)
    assert [event.remaining_points for event in events] == [98400, 99999]
    assert target.snapshot().balance.observed_at == 13


def test_selected_integrity_checks_continue_through_ambiguity():
    target = tracker()
    feed(target)
    feed(target, start=5, flow=OTHER_FLOW)
    assert target.snapshot().status == "ambiguous"
    with pytest.raises(AgrisDetectionError, match="constraints"):
        target.observe(frame(100001, index=10))
    assert target.snapshot().status == "invalid"
    assert target.snapshot().balance is None


def test_flow_and_epoch_histories_never_join():
    target = tracker()
    feed(target, VALUES[:3])
    feed(target, VALUES[3:], start=3, flow=OTHER_FLOW)
    assert target.snapshot().status == "searching"
    target = tracker()
    for index, value in enumerate(VALUES):
        target.observe(frame(value, index=index, generation=index + 1))
    assert target.snapshot().status == "searching"


def test_closed_unselected_flow_can_be_relearned_without_old_history():
    target = tracker()
    feed(target, VALUES[:3])
    target.close_flow(FLOW)
    feed(target, VALUES[3:], start=3, generation=2)
    assert target.snapshot().status == "searching"
    feed(target, [98360, 98320, 98280], start=5, generation=2)
    assert target.snapshot().status == "tracking"
    assert target.snapshot().balance.connection_epoch == 2


@pytest.mark.parametrize("action", ["close", "gap", "epoch"])
def test_selected_disconnect_gap_or_epoch_change_invalidates(action):
    target = tracker()
    feed(target)
    with pytest.raises(AgrisDetectionError):
        if action == "close":
            target.close_flow(FLOW)
        elif action == "gap":
            target.gap_reset(FLOW, 1, 500)
        else:
            target.observe(frame(98360, index=5, generation=2))
    assert target.snapshot().balance is None
    assert target.snapshot().status == "invalid"


def test_gap_before_selection_is_also_invalid():
    target = tracker()
    with pytest.raises(AgrisDetectionError, match="TCP gap"):
        target.gap_reset(OTHER_FLOW, 7, 500)
    assert target.snapshot().status == "invalid"


@pytest.mark.parametrize("change", [{"flag": 1}, {"length": 65}, {"maximum": 99999}])
def test_selected_changed_wire_shape_or_cap_is_invalid(change):
    target = tracker()
    feed(target)
    with pytest.raises(AgrisDetectionError):
        target.observe(frame(98360, index=5, **change))
    assert target.snapshot().balance is None


def test_unrelated_opcode_shapes_do_not_invalidate_selected_layout():
    target = tracker()
    feed(target)
    target.observe(frame(12345, index=5, opcode=0xFFFF, length=80, flag=1))
    status = target.snapshot()
    assert status.status == "tracking"
    assert status.balance.remaining_points == 98400
    assert status.balance.observed_at == 4


def test_declared_length_mismatch_is_ignored_before_selection_and_invalid_after():
    target = tracker()
    original = frame(98360, index=5)
    malformed = BDOFrame(5, b"\x41\x00" + original.message[2:], original.context, original.stream_sequence)
    target.observe(malformed)
    assert target.snapshot().status == "searching"
    feed(target)
    with pytest.raises(AgrisDetectionError, match="shape"):
        target.observe(malformed)


def test_cap_absent_on_first_observation_does_not_start_later_mid_family():
    target = tracker()
    target.observe(frame(99000, maximum_offset=None))
    feed(target, start=1)
    assert target.snapshot().status == "searching"


def test_changing_cap_during_learning_permanently_rejects_column():
    target = tracker()
    feed(target, VALUES[:3])
    target.observe(frame(98440, index=3, maximum=100001))
    feed(target, [98400, 98360, 98320, 98280, 98240], start=4)
    assert target.snapshot().status == "searching"


def test_out_of_range_before_selection_is_not_forgotten():
    target = tracker()
    target.observe(frame(100001))
    feed(target, start=1)
    assert target.snapshot().status == "searching"


def test_same_timestamp_equal_updates_still_emit_as_distinct_logical_records():
    events = []
    target = tracker(on_balance=events.append)
    feed(target)
    target.observe(frame(98400, index=5, timestamp=4))
    target.observe(frame(98400, index=6, timestamp=4))
    assert len(events) == 3
    assert events[0] == events[1] == events[2]


@pytest.mark.parametrize("resource", ["families", "columns", "candidates"])
def test_resource_exhaustion_never_evicts_competitors_to_claim_uniqueness(resource):
    options = AgrisDiscoveryOptions(settle_seconds=0, **{f"max_{resource}": 1})
    target = AgrisTracker(expected_maximum_points=100000, options=options)
    with pytest.raises(AgrisDetectionError, match="limit reached"):
        if resource == "families":
            target.observe(frame(99000))
            target.observe(frame(98900, opcode=0x8765))
        elif resource == "columns":
            target.observe(frame(99000))
        else:
            feed(target, duplicate_remaining=48)
    assert target.snapshot().status == "invalid"
    assert target.snapshot().balance is None


def test_first_failure_is_latched_and_cannot_be_refreshed_away():
    target = tracker()
    with pytest.raises(AgrisDetectionError, match="first"):
        target.invalidate("first")
    with pytest.raises(AgrisDetectionError, match="first"):
        target.invalidate("second")
    with pytest.raises(AgrisDetectionError, match="first"):
        target.observe(frame(98000))
    assert target.refresh(100).reason == "first"
    assert target.snapshot().status == "invalid"


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_packet_time_invalidates(timestamp):
    target = tracker()
    with pytest.raises(AgrisDetectionError, match="timestamp"):
        target.observe(frame(98000, timestamp=timestamp))


@pytest.mark.parametrize("value", [True, "123"])
def test_refresh_rejects_invalid_time_type(value):
    with pytest.raises(TypeError, match="now"):
        tracker().refresh(value)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_refresh_rejects_nonfinite_time(value):
    with pytest.raises(ValueError, match="now"):
        tracker().refresh(value)


def test_stream_versions_do_not_persist_between_trackers():
    original = tracker()
    feed(original)
    assert original.snapshot().status == "tracking"
    fresh = tracker()
    fresh.observe(frame(98360, index=5))
    assert fresh.snapshot().status == "searching"
    assert fresh.snapshot().balance is None


def test_balance_and_diagnostics_have_no_starting_consumption_or_rate_fields():
    target = tracker()
    feed(target)
    payload = target.snapshot().to_dict()
    forbidden = ("consum", "starting", "delta", "kill", "rate")

    def check(value):
        if isinstance(value, dict):
            for key, item in value.items():
                assert not any(word in key for word in forbidden)
                check(item)
        elif isinstance(value, list):
            for item in value:
                check(item)

    check(payload)
    assert payload["balance"]["remaining_points"] == 98400
