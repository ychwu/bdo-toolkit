"""Scaling and live-retention regressions for calibration."""

from __future__ import annotations

from bdo_toolkit._calibration import capture as calibration_capture
from bdo_toolkit._calibration import workflow as calibration_workflow
from typing import Iterator

import pytest

from bdo_toolkit import calibration as calibration_module
from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.calibration import (
    CalibrationRetention,
    CalibrationResult,
    CalibrationSession,
    calibrate_and_update,
    calibrate_frames,
    calibrate_live,
    collect_frames_pcap,
    detect_transfer_family,
)


_FLOW = FlowKey("203.0.113.10", 8889, "198.51.100.20", 50000)


def _frame(
    message: bytearray,
    *,
    index: int,
    opcode: int = 0x1234,
    flow: FlowKey = _FLOW,
    flow_generation: int = 1,
) -> BDOFrame:
    message[0:2] = len(message).to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    return BDOFrame(
        index=index,
        message=bytes(message),
        context=PacketContext(
            timestamp=1000.0 + index,
            flow=flow,
            flow_generation=flow_generation,
        ),
        stream_sequence=100 + index,
    )


def _record_frame(
    *,
    index: int,
    storage_context: bool,
    flow_generation: int = 1,
) -> BDOFrame:
    message = bytearray(261)
    if storage_context:
        message[8:12] = bytes.fromhex("20000000")
    message[37:41] = (7003).to_bytes(4, "little")
    message[41:45] = (3).to_bytes(4, "little")
    message[49:57] = b"\xff" * 8
    message[72:80] = b"\x22" * 8
    return _frame(
        message,
        index=index,
        flow_generation=flow_generation,
    )


def _reference_frame(*, index: int, flow_generation: int = 1) -> BDOFrame:
    message = bytearray(24)
    message[10:14] = (7003).to_bytes(4, "little")
    return _frame(
        message,
        index=index,
        opcode=0x4321,
        flow_generation=flow_generation,
    )


class _CountingFrames(list[BDOFrame]):
    yielded = 0

    def __iter__(self) -> Iterator[BDOFrame]:
        for frame in super().__iter__():
            self.yielded += 1
            yield frame


def test_auto_calibration_full_corpus_work_is_linear() -> None:
    """Candidate count must not multiply full-corpus traversals."""

    small_count = 80
    large_count = 320
    small = _CountingFrames(
        _record_frame(index=index, storage_context=True)
        for index in range(small_count)
    )
    large = _CountingFrames(
        _record_frame(index=index, storage_context=True)
        for index in range(large_count)
    )

    calibrate_frames(small, item_id=7003, quantity=3)
    calibrate_frames(large, item_id=7003, quantity=3)

    # Index construction, two auto-direction candidate passes, and retention
    # byte accounting each traverse the source once. Allow one spare pass so
    # this assertion is structural rather than timing-sensitive.
    assert small.yielded <= 5 * small_count
    assert large.yielded <= 5 * large_count
    assert large.yielded <= 5 * small.yielded


def test_equal_frame_objects_use_identity_for_context_boundary() -> None:
    reference = _reference_frame(index=0)
    first_record = _record_frame(index=1, storage_context=False)
    second_record = _record_frame(index=1, storage_context=False)
    assert first_record == second_record

    family, has_reference, context_label, storage_context = detect_transfer_family(
        [reference, first_record, second_record],
        second_record,
        37,
        7003,
    )

    # The equal first record is an adjacent-transaction boundary. Equality-
    # based list.index() used to resolve the target to that first occurrence
    # and incorrectly inherit the older reference.
    assert (family, has_reference, context_label, storage_context) == (
        None,
        False,
        False,
        False,
    )


def test_reference_context_does_not_cross_flow_generation() -> None:
    reference = _reference_frame(index=0, flow_generation=1)
    record = _record_frame(
        index=1,
        storage_context=False,
        flow_generation=2,
    )

    family, has_reference, _, _ = detect_transfer_family(
        [reference, record],
        record,
        37,
        7003,
    )

    assert family is None
    assert not has_reference


def test_offline_calibration_collector_tracks_connection_generations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_replay(path, manager) -> None:
        seen["manager"] = manager

    monkeypatch.setattr(calibration_capture, "replay_pcap_file", fake_replay)

    assert collect_frames_pcap("unused.pcapng") == []
    manager = seen["manager"]
    assert manager._track_flow_generations is True  # type: ignore[attr-defined]


class _FakeLivePacketCapture:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.running = False
        self.error = None

    def start(self) -> None:
        self.running = True

    def stop(self) -> None:
        self.running = False

    def raise_if_failed(self) -> None:
        return None


def test_live_retention_keeps_newest_tail_and_reports_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        calibration_capture,
        "LivePacketCapture",
        _FakeLivePacketCapture,
    )
    session = CalibrationSession(
        item_id=7003,
        context_frames=1,
        max_retained_frames=3,
        max_retained_bytes=1_000,
    )
    session.start()
    assert session._manager is not None
    assert session._manager._track_flow_generations is True
    observed = [
        _frame(bytearray(10), index=index, opcode=0x1000 + index)
        for index in range(5)
    ]
    for frame in observed:
        session._retain_frame(frame)

    assert session.frames_collected == 5
    assert session.frames_observed == 5
    assert session.frames_retained == 3
    assert session.frames_discarded == 2
    assert session.bytes_observed == 50
    assert session.bytes_retained == 30
    assert session.bytes_discarded == 20
    assert session.retention_truncated
    assert list(session._frames) == observed[-3:]

    result = session.stop()

    assert result.frames_scanned == 3
    assert result.retention.frames_observed == 5
    assert result.retention.frames_retained == 3
    assert result.retention.frames_discarded == 2
    assert result.retention.bytes_observed == 50
    assert result.retention.bytes_retained == 30
    assert result.retention.bytes_discarded == 20
    assert result.retention.truncated
    assert result.to_json_dict()["retention"] == {
        "frames_observed": 5,
        "frames_retained": 3,
        "frames_discarded": 2,
        "bytes_observed": 50,
        "bytes_retained": 30,
        "bytes_discarded": 20,
        "max_retained_frames": 3,
        "max_retained_bytes": 1_000,
        "truncated": True,
    }
    assert "live retention truncated" in result.summary()


def test_live_calibration_bounds_reassembly_flows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        calibration_capture,
        "LivePacketCapture",
        _FakeLivePacketCapture,
    )
    session = CalibrationSession(item_id=7003)
    session.start()
    manager = session._manager
    assert manager is not None
    assert manager._max_flows == 64
    assert manager._idle_timeout is None

    for index in range(65):
        manager.process_tcp_segment(
            source_ip="203.0.113.10",
            source_port=8889,
            destination_ip="198.51.100.20",
            destination_port=40_000 + index,
            sequence=1_000,
            payload=b"\x01",
            timestamp=float(index),
        )

    assert len(manager._flows) == 64
    assert FlowKey(
        "203.0.113.10", 8889, "198.51.100.20", 40_000
    ) not in manager._flows
    assert manager._next_flow_generation == 65

    session.stop()
    assert not manager._flows


def test_live_retention_enforces_payload_byte_limit() -> None:
    session = CalibrationSession(
        item_id=7003,
        context_frames=1,
        max_retained_frames=10,
        max_retained_bytes=25,
    )
    for index, length in enumerate((10, 12, 8)):
        session._retain_frame(_frame(bytearray(length), index=index))

    retention = session.retention
    assert retention.frames_observed == 3
    assert retention.frames_retained == 2
    assert retention.frames_discarded == 1
    assert retention.bytes_observed == 30
    assert retention.bytes_retained == 20
    assert retention.bytes_discarded == 10
    assert retention.truncated


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_retained_frames": 0}, "positive integer"),
        ({"max_retained_frames": True}, "positive integer"),
        ({"max_retained_frames": 5}, "greater than context_frames"),
        ({"max_retained_bytes": 0}, "positive integer"),
        ({"max_retained_bytes": False}, "positive integer"),
    ],
)
def test_live_retention_limits_are_validated(
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        CalibrationSession(item_id=7003, **kwargs)  # type: ignore[arg-type]


def test_offline_result_reports_complete_unbounded_retention() -> None:
    frames = [_frame(bytearray(10), index=0), _frame(bytearray(12), index=1)]

    result = calibrate_frames(frames, item_id=7003)

    assert result.frames_scanned == result.retention.frames_retained == 2
    assert result.retention.frames_observed == 2
    assert not result.retention.truncated
    assert not result.retention.bounded
    assert result.retention.bytes_observed == 22


def test_calibration_retention_rejects_inconsistent_accounting() -> None:
    valid: dict[str, object] = {
        "frames_observed": 3,
        "frames_retained": 2,
        "frames_discarded": 1,
        "bytes_observed": 30,
        "bytes_retained": 20,
        "bytes_discarded": 10,
    }
    invalid_cases = (
        ({**valid, "frames_observed": -1}, "non-negative integer"),
        ({**valid, "frames_observed": 4}, "must equal frames_observed"),
        ({**valid, "bytes_observed": None}, "all set or all None"),
        ({**valid, "bytes_observed": 31}, "must equal bytes_observed"),
        ({**valid, "max_retained_frames": 0}, "positive integer"),
        ({**valid, "max_retained_frames": 1}, "exceeds max_retained_frames"),
        ({**valid, "max_retained_bytes": 19}, "exceeds max_retained_bytes"),
    )

    for kwargs, message in invalid_cases:
        with pytest.raises(ValueError, match=message):
            CalibrationRetention(**kwargs)  # type: ignore[arg-type]


def test_result_rejects_retention_that_does_not_match_scored_frames() -> None:
    retention = CalibrationRetention(5, 3, 2, 50, 30, 20)

    with pytest.raises(ValueError, match="frames_scanned"):
        CalibrationResult((), (), 4, retention=retention)


def test_bounded_live_result_reports_retention_without_eviction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        calibration_capture,
        "LivePacketCapture",
        _FakeLivePacketCapture,
    )
    session = CalibrationSession(
        item_id=7003,
        context_frames=1,
        max_retained_frames=3,
        max_retained_bytes=1_000,
    )
    session.start()
    session._retain_frame(_frame(bytearray(10), index=0))
    session._retain_frame(_frame(bytearray(12), index=1))

    result = session.stop()

    assert result.frames_scanned == 2
    assert result.retention.frames_observed == 2
    assert result.retention.frames_retained == 2
    assert result.retention.frames_discarded == 0
    assert result.retention.bounded
    assert not result.retention.truncated


def test_calibrate_and_update_forwards_live_retention_options(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_calibrate_live(**kwargs: object) -> CalibrationResult:
        seen.update(kwargs)
        return CalibrationResult(
            specs=(),
            ignored=(),
            frames_scanned=0,
            retention=CalibrationRetention(0, 0, 0, 0, 0, 0),
        )

    monkeypatch.setattr(calibration_workflow, "calibrate_live", fake_calibrate_live)

    result, update = calibrate_and_update(
        tmp_path / "opcodes.json",
        item_id=7003,
        max_retained_frames=321,
        max_retained_bytes=65_432,
    )

    assert result.specs == ()
    assert update is None
    assert seen["max_retained_frames"] == 321
    assert seen["max_retained_bytes"] == 65_432


def test_calibrate_live_forwards_retention_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    canned = CalibrationResult(
        specs=(),
        ignored=(),
        frames_scanned=0,
        retention=CalibrationRetention(0, 0, 0, 0, 0, 0),
    )

    class FakeSession:
        def __init__(self, **kwargs: object) -> None:
            seen.update(kwargs)

        def __enter__(self) -> "FakeSession":
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            return None

        def raise_if_failed(self) -> None:
            return None

        def stop(self) -> CalibrationResult:
            return canned

    monkeypatch.setattr(calibration_capture, "CalibrationSession", FakeSession)

    result = calibrate_live(
        item_id=7003,
        capture_seconds=0,
        max_retained_frames=321,
        max_retained_bytes=65_432,
    )

    assert result is canned
    assert seen["max_retained_frames"] == 321
    assert seen["max_retained_bytes"] == 65_432


def test_custom_live_retention_is_rejected_for_offline_calibration(
    tmp_path,
) -> None:
    with pytest.raises(ValueError, match="max_retained_frames.*live calibration"):
        calibrate_and_update(
            tmp_path / "opcodes.json",
            item_id=7003,
            pcap="capture.pcapng",
            max_retained_frames=321,
        )
