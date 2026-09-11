"""Live evidence revisions, batch parity, and terminal ownership."""

import asyncio
from dataclasses import replace
from threading import Event, Thread

import pytest

from bdo_toolkit import AsyncCalibrationSession
from bdo_toolkit._calibration import capture as capture_module
from bdo_toolkit._calibration.analysis import assess_frames
from bdo_toolkit._calibration.live import LiveCalibration
from bdo_toolkit._calibration.progress import readiness_issues
from bdo_toolkit._protocol import BDOFrame, FlowKey, PacketContext
from bdo_toolkit.calibration import (
    CalibrationAuthorityError, CalibrationProgress, CalibrationSession,
    calibrate_frames,
)


def frame(message, opcode, index=0):
    message[:2] = len(message).to_bytes(2, "little")
    message[3:5] = opcode.to_bytes(2, "little")
    return BDOFrame(index, bytes(message), PacketContext(
        1000.0 + index, FlowKey("203.0.113.1", 8889, "198.51.100.2", 50000),
    ), 100 + index)


def record(count=1, *, storage=True, preview=False, index=0):
    offset, base, stride = (37, 261, 226) if storage else (31, 254, 228)
    data = bytearray(base + (count - 1) * stride)
    if storage:
        data[6:8] = count.to_bytes(2, "little")
        data[8:12] = (32).to_bytes(4, "little")
    else:
        data[27:31] = bytes.fromhex("d0f205a3")
    for i in range(count):
        at = offset + i * stride
        data[at:at + 4] = (99123).to_bytes(4, "little")
        data[at + 4:at + 8] = (1).to_bytes(4, "little")
        data[at + 12:at + 20] = b"\xff" * 8
        data[at + 35:at + 43] = b"\xff" * 8 if preview else (0x123400 + i).to_bytes(8, "little")
    return frame(data, 0xAB01 if storage else 0xAB02, index)


def decrement(count=1, index=0):
    data = bytearray(52 + (count - 1) * 23)
    for i in range(count):
        at = i * 23
        data[34 + at:42 + at] = (0x123400 + i).to_bytes(8, "little")
        data[42 + at:46 + at] = (1).to_bytes(4, "little")
    return frame(data, 0xAB03, index)


def transfer_frames():
    return [decrement(), record(), decrement(4, 1), record(4, index=1),
            record(5, storage=False, index=2)]


def observations(frames, **overrides):
    from bdo_toolkit._calibration.observations import observe_transfers
    options = dict(item_id=99123, quantity=1, action="auto", context_frames=5,
                   min_confidence=0.8, run_id="test-run", frames_discarded=0)
    options.update(overrides)
    return observe_transfers(frames, **options)


def test_observation_prefix_counts_and_stable_identity():
    frames = transfer_frames()
    previous = ()
    for end, expected in [(0, []), (1, []), (2, [1]), (3, [1]),
                          (4, [1, 4]), (5, [1, 4, 5])]:
        current = observations(frames[:end])
        assert [o.record_count for o in current] == expected
        assert [o.item_record_count for o in current] == expected
        assert [o.item_quantity for o in current] == expected
        assert current[:len(previous)] == previous
        previous = current
    assert [o.direction for o in current] == ["inventory-to-storage"] * 2 + ["storage-to-inventory"]
    assert [o.frame_number for o in current] == [2, 4, 5]
    assert observations(frames[2:], frames_discarded=2) == current[1:]
    # If the first retained frame loses its source context, retract it too.
    assert observations(frames[3:], frames_discarded=3) == current[2:]
    restarted = observations(frames, run_id="new-run")
    assert set(o.observation_id for o in current).isdisjoint(o.observation_id for o in restarted)


def test_first_deposit_observation_does_not_promote_layout():
    session = CalibrationSession(item_id=99123, quantity=1)
    for value in transfer_frames()[:2]:
        session._retain_frame(value)
    controller = LiveCalibration(session, stop_on_complete=False, on_update=None)
    update = controller._assess()
    assert not update.ready and not update.specs
    assert update.observations[0].record_count == 1
    assert update.observations[0].direction == "inventory-to-storage"


@pytest.mark.parametrize("mutation", ["missing", "instance", "quantity", "flow", "generation", "stale", "header"])
def test_deposit_observation_requires_fresh_linked_decrement(mutation):
    source, target = decrement(), record()
    if mutation == "missing":
        frames = [target]
    elif mutation == "stale":
        frames = [source, record(), target]
    elif mutation in ("flow", "generation"):
        context = replace(source.context, flow_generation=1) if mutation == "generation" else replace(
            source.context, flow=replace(source.context.flow, destination_port=50001))
        frames = [replace(source, context=context), target]
    else:
        data = bytearray(source.message)
        at = {"instance": 34, "quantity": 42, "header": 0}[mutation]
        data[at] ^= 8
        frames = [replace(source, message=bytes(data)), target]
    found = observations(frames)
    assert not found or (mutation == "stale" and [o.frame_number for o in found] == [2])


@pytest.mark.parametrize("mutation", ["header", "marker", "instance", "quantity", "tail", "ambiguous-town"])
def test_malformed_or_ambiguous_deposit_is_not_guidance(mutation):
    target = record(4)
    data = bytearray(target.message)
    at = {"header": 0, "marker": 37 + 3 * 226 + 12,
          "instance": 37 + 3 * 226 + 35, "quantity": 41,
          "tail": len(data) - 1, "ambiguous-town": 8}[mutation]
    if mutation == "instance":
        data[at:at + 8] = bytes(8)
    elif mutation == "tail":
        data = data[:37 + 3 * 226 + 15]
        data[:2] = len(data).to_bytes(2, "little")
    elif mutation == "ambiguous-town":
        data[at:at + 4] = (0x058C).to_bytes(4, "little")
    else:
        data[at] ^= 8
    assert not observations([decrement(4), replace(target, message=bytes(data))])


@pytest.mark.parametrize("source", ["85fa5745", "0471ee0e", "00000000"])
def test_other_inventory_receipts_are_not_withdrawals(source):
    target = record(storage=False)
    data = bytearray(target.message)
    data[27:31] = bytes.fromhex(source)
    assert not observations([replace(target, message=bytes(data))])


def test_conflicting_or_duplicate_receipt_sources_are_not_guidance():
    for raw in (bytes.fromhex("85fa5745"), bytes.fromhex("d0f205a3")):
        target = record(storage=False)
        data = bytearray(target.message)
        data[10:14] = raw
        assert not observations([replace(target, message=bytes(data))])


def test_skipped_middle_record_cannot_look_like_a_two_record_batch():
    for storage in (False, True):
        target = record(3, storage=storage)
        data = bytearray(target.message)
        at = 37 + 226 if storage else 31 + 228
        data[at:at + 4] = (99124).to_bytes(4, "little")
        data[at + 12:at + 20] = bytes(8)
        assert not observations([decrement(3), replace(target, message=bytes(data))])


def test_record_counts_are_not_quantities_or_watched_item_counts():
    target = record(4, storage=False)
    data = bytearray(target.message)
    data[31 + 228:35 + 228] = (99124).to_bytes(4, "little")
    value, = observations([replace(target, message=bytes(data))])
    assert (value.record_count, value.item_record_count, value.item_quantity) == (4, 3, 3)
    target = record(storage=False)
    data = bytearray(target.message)
    data[35:39] = (5).to_bytes(4, "little")
    assert not observations([replace(target, message=bytes(data))])
    value, = observations([replace(target, message=bytes(data))], quantity=None)
    assert (value.record_count, value.item_record_count, value.item_quantity) == (1, 1, 5)


def test_observation_action_filter_and_preview_exclusion():
    frames = transfer_frames()
    assert len(observations(frames, action="inventory-to-storage")) == 2
    assert len(observations(frames, action="storage-to-inventory")) == 1
    assert not observations(frames, action="loot-preview")
    assert not observations([record(storage=False, preview=True)])
    assert not observations(frames, min_confidence=1.0)


def test_new_observation_emits_even_without_new_opcode_or_layout():
    session = CalibrationSession(item_id=99123, quantity=1)
    updates = []
    controller = LiveCalibration(session, stop_on_complete=False, on_update=updates.append)
    for _ in range(2):
        for value in (decrement(), record()):
            session._retain_frame(value)
        controller._emit(controller._assess())
        controller._emit(controller._assess())
    assert len(updates) == 2
    assert updates[0].specs == updates[1].specs == ()
    assert [len(u.observations) for u in updates] == [1, 2]
    assert len({o.observation_id for o in updates[-1].observations}) == 2


def test_observation_model_is_additive_frozen_and_serializable():
    import pickle
    from dataclasses import FrozenInstanceError
    from bdo_toolkit.calibration import CalibrationObservation
    value, = observations(transfer_frames()[:2])
    assert isinstance(value, CalibrationObservation)
    assert pickle.loads(pickle.dumps(value)) == value
    with pytest.raises(FrozenInstanceError):
        value.record_count = 5
    update = CalibrationProgress("progress", (), (), frozenset(), (), False,
                                 CalibrationSession(item_id=99123).retention, None)
    assert update.observations == ()
    assert update.to_json_dict()["observations"] == []
    exported = replace(update, observations=(value,)).to_json_dict()["observations"][0]
    assert exported == dict(observation_id="test-run:2", frame_number=2,
                           direction="inventory-to-storage", opcode="0xAB01", item_id=99123,
                           record_count=1, item_record_count=1, item_quantity=1)


def test_observations_are_not_required_for_auto_completion(monkeypatch):
    from bdo_toolkit._calibration import live
    monkeypatch.setattr(live, "observe_transfers", lambda *args, **kwargs: ())
    with CalibrationSession(item_id=99123, quantity=1, stop_on_complete=True) as session:
        for value in transfer_frames():
            session._retain_frame(value)
        assert session.wait(2) is not None
        assert session.progress.ready and session.progress.observations == ()


class FakeCapture:
    def __init__(self, **kwargs):
        self.running = False
        self.stopped = False
        self.cleanup_incomplete = False
        self.error = None
        self.stop_calls = 0

    def start(self):
        self.running = True

    def stop(self):
        self.stop_calls += 1
        self.running = False
        self.stopped = True

    def raise_if_failed(self):
        if self.error is not None:
            raise self.error


@pytest.fixture(autouse=True)
def fake_capture(monkeypatch):
    monkeypatch.setattr(capture_module, "LivePacketCapture", FakeCapture)
    monkeypatch.setattr(LiveCalibration, "INTERVAL", 0.005)


def test_each_prefix_preserves_batch_outcome_and_readiness():
    frames = transfer_frames()
    for end in range(len(frames) + 1):
        assessment = assess_frames(frames[:end], item_id=99123, quantity=1)
        if assessment.error is not None:
            with pytest.raises(type(assessment.error)) as caught:
                calibrate_frames(frames[:end], item_id=99123, quantity=1)
            assert str(caught.value) == str(assessment.error)
        else:
            assert assessment.result == calibrate_frames(frames[:end], item_id=99123, quantity=1)
        ready = assessment.error is None and not readiness_issues(assessment.result, "auto")
        assert ready is (end == len(frames))
    assert assessment.result.specs_by_event()["SOURCE_STACK_DECREMENT"][0].repeat_stride == 23


def test_live_auto_stop_final_result_equals_batch():
    updates = []
    frames = transfer_frames()
    with CalibrationSession(item_id=99123, quantity=1, stop_on_complete=True,
                            on_update=updates.append) as session:
        capture = session._capture
        for value in frames:
            session._retain_frame(value)
        result = session.wait(2)
        assert result is not None
        assert session.stop() is result
        assert session.result is result
        assert session.stopped and not session.running
        assert session.stop_reason == "complete"
        assert capture.stop_calls == 1
    batch = calibrate_frames(frames, item_id=99123, quantity=1)
    assert replace(result, retention=batch.retention) == batch
    assert [u.kind for u in updates][-2:] == ["finalizing", "finished"]
    assert updates[-1].result is result
    assert [o.record_count for o in updates[-1].observations] == [1, 4, 5]
    assert updates[-2].observations == updates[-1].observations
    assert updates[-1].to_json_dict()["ready"] is True


def test_first_deposit_is_progress_not_terminal_failure():
    observed = Event()
    with pytest.raises(CalibrationAuthorityError), CalibrationSession(item_id=99123, quantity=1, stop_on_complete=True,
                            on_update=lambda u: observed.set() if u.detected_opcodes else None) as session:
        session._retain_frame(record())
        assert observed.wait(2)
        assert session.running and session.error is None
        assert not session.progress.ready
        assert session.progress.detected_opcodes == (0xAB01,)
        assert session.wait(0) is None
        with pytest.raises(CalibrationAuthorityError):
            session.stop()


def test_finalization_can_invalidate_ready_assessment(monkeypatch):
    with pytest.raises(CalibrationAuthorityError), CalibrationSession(item_id=99123, quantity=1, stop_on_complete=True) as session:
        manager = session._manager
        finish = manager.finish
        def conflicting_finish():
            # Another valid wrapper geometry locates the count elsewhere.
            value = record(2, index=4)
            data = bytearray(value.message)
            data[6:8] = b"\0\0"
            data[14:16] = (2).to_bytes(2, "little")
            session._retain_frame(replace(value, message=bytes(data)))
            finish()
        monkeypatch.setattr(manager, "finish", conflicting_finish)
        for value in transfer_frames():
            session._retain_frame(value)
        with pytest.raises(CalibrationAuthorityError):
            session.wait(2)
        assert session.result is None
        assert session.stop_reason == "error"
        assert session.stopped
        # The context also surfaces a stored background failure.
        with pytest.raises(CalibrationAuthorityError):
            session.stop()


def test_progress_retracts_after_retention_eviction():
    ready, retracted = Event(), Event()
    def observe(update):
        if update.ready:
            ready.set()
        elif ready.is_set():
            retracted.set()
    with CalibrationSession(item_id=99123, quantity=1, on_update=observe,
                            context_frames=1, max_retained_frames=6) as session:
        for value in transfer_frames():
            session._retain_frame(value)
        assert ready.wait(2)
        for i in range(7):
            session._retain_frame(frame(bytearray(10), 0xDD00, i))
        assert retracted.wait(2)
        assert not session.progress.ready
        assert not session.progress.specs
        assert not session.progress.observations
        assert session.progress.retention.truncated
        result = session.stop()
        assert not result.specs


def test_callback_can_request_stop_but_cannot_block():
    errors = []
    session = None
    def observe(update):
        if update.kind != "progress":
            return
        for operation in (session.stop, session.wait):
            with pytest.raises(RuntimeError, match="on_update"):
                operation()
            errors.append(True)
        session.request_stop()
    with CalibrationSession(item_id=99123, on_update=observe) as session:
        result = session.wait(2)
        assert result is not None and not result.specs
        assert session.stop_reason == "requested"
    assert len(errors) == 2


def test_callback_failure_stops_capture_and_surfaces_identity():
    failure = LookupError("consumer failed")
    def observe(update):
        raise failure
    session = CalibrationSession(item_id=99123, on_update=observe)
    session.start()
    capture = session._capture
    with pytest.raises(LookupError) as caught:
        session.wait(2)
    assert caught.value is failure
    # wait can observe the failure before the worker finishes cleanup.
    session._live.thread.join(2)
    assert capture.stopped and session.result is None
    with pytest.raises(LookupError):
        session.__exit__(None, None, None)


def test_finished_callback_settles_before_wait_returns():
    entered, release = Event(), Event()
    def observe(update):
        if update.kind == "finished":
            entered.set()
            assert release.wait(2)
    session = CalibrationSession(item_id=99123, on_update=observe, stop_on_complete=True)
    session.start()
    try:
        for value in transfer_frames():
            session._retain_frame(value)
        assert entered.wait(2)
        assert not session.stopped and session.result is None
    finally:
        release.set()
        session._live.thread.join(2)
        session.stop()


@pytest.mark.parametrize("action,frames", [
    ("loot-preview", [record(storage=False, preview=True)]),
    ("storage-to-inventory", [record(storage=False)]),
    ("inventory-to-storage", transfer_frames()[:-1]),
])
def test_action_specific_completion(action, frames):
    with CalibrationSession(item_id=99123, quantity=1, action=action,
                            stop_on_complete=True) as session:
        for value in frames:
            session._retain_frame(value)
        result = session.wait(2)
        assert result is not None
        assert session.progress.ready


def test_async_wait_timeout_cancel_and_completion():
    async def run():
        async with AsyncCalibrationSession(item_id=99123, quantity=1,
                                           stop_on_complete=True) as session:
            assert await session.wait(0) is None
            pending = asyncio.create_task(session.wait())
            await asyncio.sleep(0.02)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert session.running
            for value in transfer_frames():
                session._session._retain_frame(value)
            result = await session.wait(2)
            assert result is not None and session.result is result
            assert await session.stop() is result
            assert session.stopped and session.stop_reason == "complete"
    asyncio.run(run())


@pytest.mark.parametrize("timeout", [None, 2, 0])
@pytest.mark.parametrize("outcome", ["success", "error", "discard"])
def test_async_wait_rechecks_completion_after_empty_poll(timeout, outcome):
    from types import SimpleNamespace

    expected = calibrate_frames(transfer_frames(), item_id=99123, quantity=1)
    failure = RuntimeError("terminal capture failure")
    calls = []
    backend = SimpleNamespace(stopped=False, result=None)

    def wait(seconds):
        calls.append(seconds)
        if len(calls) == 1:
            # The poll timed out, then capture completed before asyncio resumed.
            backend.result = expected if outcome == "success" else None
            backend.stopped = True
            return None
        assert seconds == 0
        if outcome == "error":
            raise failure
        return backend.result

    backend.wait = wait

    async def run():
        session = AsyncCalibrationSession(item_id=99123, quantity=1)
        session._session = backend
        if outcome == "error":
            with pytest.raises(RuntimeError) as caught:
                await session.wait(timeout)
            assert caught.value is failure
        else:
            result = await session.wait(timeout)
            assert result is (expected if outcome == "success" else None)
            assert session.result is result
        assert len(calls) == 2

    asyncio.run(run())


def test_async_terminal_recheck_settles_before_cancellation_escapes():
    from types import SimpleNamespace

    entered, release, settled = Event(), Event(), Event()
    backend = SimpleNamespace(stopped=False)
    calls = []

    def wait(seconds):
        calls.append(seconds)
        if len(calls) == 1:
            backend.stopped = True
            return None
        assert seconds == 0
        entered.set()
        try:
            assert release.wait(2)
            raise RuntimeError("failure while the caller is cancelling")
        finally:
            settled.set()

    backend.wait = wait

    async def run():
        session = AsyncCalibrationSession(item_id=99123)
        session._session = backend
        pending = asyncio.create_task(session.wait())
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            pending.cancel()
            await asyncio.sleep(0)  # Deliver cancellation while the worker is held.
            assert not pending.done()
        finally:
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await pending
        assert settled.is_set()
        assert len(calls) == 2

    asyncio.run(run())


def test_slow_callback_retains_worker_for_bounded_cleanup_retry(monkeypatch):
    entered, release = Event(), Event()
    def observe(update):
        if update.kind == "progress":
            entered.set()
            release.wait(2)
    monkeypatch.setattr(LiveCalibration, "JOIN_TIMEOUT", 0.02)
    session = CalibrationSession(item_id=99123, on_update=observe)
    session.start()
    try:
        assert entered.wait(2)
        with pytest.raises(RuntimeError, match="worker cleanup is incomplete") as caught:
            session.stop()
        assert caught.value.cleanup_owner is session
        assert session.cleanup_incomplete and session._capture is not None
    finally:
        release.set()
        session._live.thread.join(2)
        result = session.stop()
    assert result is not None and not session.cleanup_incomplete


def test_final_scoring_does_not_lock_observation_or_allow_restart(monkeypatch):
    entered, release = Event(), Event()
    original = capture_module.calibrate_frames
    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return original(*args, **kwargs)
    monkeypatch.setattr(capture_module, "calibrate_frames", delayed)
    session = CalibrationSession(item_id=99123, stop_on_complete=True)
    session.start()
    try:
        for value in transfer_frames():
            session._retain_frame(value)
        assert entered.wait(2)
        assert session.wait(0) is None
        assert not session.running
        with pytest.raises(RuntimeError, match="already running"):
            session.start()
    finally:
        release.set()
        session._live.thread.join(2)
        session.stop()


def test_concurrent_stops_share_finalization():
    session = CalibrationSession(item_id=99123)
    session.start()
    capture = session._capture
    results = []
    workers = [Thread(target=lambda: results.append(session.stop())) for _ in range(3)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(2)
        assert not worker.is_alive()
    assert len(results) == 3 and all(r is results[0] for r in results)
    assert capture.stop_calls == 1


@pytest.mark.parametrize("loss", ["retention", "flow", "native"])
def test_known_loss_prevents_auto_stop_but_manual_batch_result_survives(loss):
    updated = Event()
    session = CalibrationSession(item_id=99123, quantity=1, stop_on_complete=True,
                                 on_update=lambda u: updated.set() if u.specs else None)
    with session:
        if loss == "retention":
            # Model an earlier tail eviction without removing the valid sequence.
            with session._retention_lock:
                session._frames_observed = session._frames_discarded = 1
        elif loss == "flow":
            session._record_flow_eviction()
        else:
            from types import SimpleNamespace
            session._capture.snapshot_stats = lambda: SimpleNamespace(dropped=1, interface_dropped=0)
        for value in transfer_frames():
            session._retain_frame(value)
        assert updated.wait(2)
        assert not session.progress.ready and session.running
        assert session.wait(0) is None
        result = session.stop()
        assert result.specs
        assert not session.progress.ready


@pytest.mark.parametrize("order", [(0, 1, 2), (1, 0, 2), (2, 1, 0)])
def test_fragmented_reordered_stream_reaches_same_layouts(order):
    values = transfer_frames()
    stream = b"".join(v.message for v in values)
    starts = [0, 101, len(stream) - 100]
    chunks = [stream[:starts[1]], stream[starts[1]:starts[2]], stream[starts[2]:]]
    with CalibrationSession(item_id=99123, quantity=1, stop_on_complete=True) as session:
        manager = session._manager
        def send(seq, payload, **kwargs):
            manager.process_tcp_segment(
                source_ip="203.0.113.1", source_port=8889,
                destination_ip="198.51.100.2", destination_port=50000,
                sequence=seq & 0xFFFFFFFF, payload=payload, timestamp=1000.0,
                **kwargs,
            )
        base = 0xFFFFFF00
        send(base - 1, b"", syn=True)
        for index in order:
            send(base + starts[index], chunks[index])
        result = session.wait(2)
        assert result is not None
    expected = calibrate_frames(values, item_id=99123, quantity=1)
    assert [s.dedupe_key() for s in result.specs] == [s.dedupe_key() for s in expected.specs]


def test_idle_worker_does_not_rescore_unchanged_window(monkeypatch):
    calls = []
    observed = Event()
    original = LiveCalibration._assess
    def assess(self):
        calls.append(True)
        return original(self)
    monkeypatch.setattr(LiveCalibration, "_assess", assess)
    with CalibrationSession(item_id=99123, on_update=lambda u: observed.set()) as session:
        assert observed.wait(2)
        assert session.wait(0.04) is None
        assert len(calls) == 1
        session.stop()


def test_calibrate_live_automatic_completion():
    from bdo_toolkit.calibration import calibrate_live
    # The facade's auto completion is exercised separately from the new wait API.
    original = CalibrationSession.start
    def start(self):
        original(self)
        for value in transfer_frames():
            self._retain_frame(value)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(CalibrationSession, "start", start)
        result = calibrate_live(item_id=99123, quantity=1, stop_on_complete=True,
                                capture_seconds=2)
    assert len(result.events_found) >= 3


@pytest.mark.parametrize("options", [{"stop_on_complete": 1}, {"on_update": 1}])
def test_invalid_live_options_fail_before_start(options):
    with pytest.raises(TypeError):
        CalibrationSession(item_id=99123, **options)


def test_async_callbacks_rejected_without_leaking_coroutines():
    async def callback(update):
        pass

    class AsyncCallback:
        async def __call__(self, update):
            pass

    for value in (callback, AsyncCallback()):
        with pytest.raises(TypeError, match="synchronous"):
            CalibrationSession(item_id=99123, on_update=value)

    # Constructor validation cannot see through an ordinary sync wrapper.
    with pytest.raises(TypeError, match="awaitable"):
        with CalibrationSession(item_id=99123, on_update=lambda u: callback(u)) as session:
            session.wait(2)
    assert not session.running and session.result is None


def test_capture_health_change_retracts_ready_without_new_frames():
    from types import SimpleNamespace

    ready, retracted = Event(), Event()
    def update(value):
        if value.ready:
            ready.set()
        elif ready.is_set():
            retracted.set()

    with CalibrationSession(item_id=99123, quantity=1, on_update=update) as session:
        stats = SimpleNamespace(dropped=0, interface_dropped=0)
        session._capture.snapshot_stats = lambda: stats
        for value in transfer_frames():
            session._retain_frame(value)
        assert ready.wait(2)
        stats.dropped = 1
        assert retracted.wait(2)
        assert not session.progress.ready
        assert session.stop().specs


def test_native_loss_reported_only_at_shutdown_refuses_completion():
    from types import SimpleNamespace

    with pytest.raises(CalibrationAuthorityError, match="dropped packets"):
        with CalibrationSession(item_id=99123, quantity=1, stop_on_complete=True) as session:
            capture = session._capture
            capture.snapshot_stats = lambda: SimpleNamespace(
                dropped=int(capture.stopped), interface_dropped=0,
            )
            for value in transfer_frames():
                session._retain_frame(value)
            session.wait(2)
    assert session.result is None and not session.running


def test_progress_model_serialization_and_immutability():
    from dataclasses import FrozenInstanceError

    with CalibrationSession(item_id=99123, on_update=lambda u: None) as session:
        result = session.stop()
        progress = session.progress
        assert isinstance(progress, CalibrationProgress)
        assert progress.to_json_dict()["result"] == result.to_json_dict()
        with pytest.raises(FrozenInstanceError):
            progress.ready = True


def test_async_context_preserves_automatic_result_without_wait():
    async def run():
        loop = asyncio.get_running_loop()
        finished = asyncio.Event()
        async with AsyncCalibrationSession(
            item_id=99123, quantity=1, stop_on_complete=True,
            on_update=lambda u: loop.call_soon_threadsafe(finished.set)
            if u.kind == "finished" else None,
        ) as session:
            for value in transfer_frames():
                session._session._retain_frame(value)
            await asyncio.wait_for(finished.wait(), 2)
        assert session.result is not None
        assert session.result is session._session.result
    asyncio.run(run())
