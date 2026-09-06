"""Worker ownership for live calibration assessments and finalization.

Capture retains frames using its existing reassembly path. This worker owns at
most one snapshot at a time; it never performs scoring on the capture callback.
"""

from __future__ import annotations

import inspect
from contextvars import ContextVar
from dataclasses import replace
from threading import Event, Lock, Thread, current_thread
from typing import TYPE_CHECKING, Callable

from .._capture_runtime import _attach_cleanup_owner
from .analysis import assess_frames
from .models import CalibrationAuthorityError, CalibrationResult
from .progress import CalibrationProgress, readiness_issues, required_events

if TYPE_CHECKING:
    from .capture import CalibrationSession


_callback_owner: ContextVar[object | None] = ContextVar("calibration_callback_owner", default=None)


class LiveCalibration:
    INTERVAL = 0.2
    JOIN_TIMEOUT = 5.0

    def __init__(
        self, session: CalibrationSession, *, stop_on_complete: bool,
        on_update: Callable[[CalibrationProgress], object] | None,
    ) -> None:
        self.session = session
        self.stop_on_complete = stop_on_complete
        self.on_update = on_update
        self.enabled = stop_on_complete or on_update is not None
        self.cancelled = Event()
        self.requested = Event()
        self.done = Event()
        self.finalizing = Event()
        self.in_callback = Event()
        self.progress: CalibrationProgress | None = None
        self.result: CalibrationResult | None = None
        self.stop_reason: str | None = None
        self.cleanup_incomplete = False
        self._callback_failed = False
        self._finish_lock = Lock()
        self.thread = Thread(target=self._run, name="calibration-assessment", daemon=True)

    def check_callback(self) -> None:
        if _callback_owner.get() is self or current_thread() is self.thread:
            raise RuntimeError(
                "blocking calibration operations cannot run inside on_update; "
                "use request_stop()"
            )

    def join(self) -> None:
        self.check_callback()
        self.cancelled.set()
        if self.thread.ident is None:
            return
        self.thread.join(self.JOIN_TIMEOUT)
        if self.thread.is_alive():
            self.cleanup_incomplete = True
            error = RuntimeError("calibration worker cleanup is incomplete; retry stop()")
            _attach_cleanup_owner(error, self.session, context="live calibration worker")
            raise error
        self.cleanup_incomplete = False

    def _emit(self, update: CalibrationProgress) -> None:
        previous = self.progress
        self.progress = update
        # Counters remain fresh, but callbacks announce semantic changes only.
        def key(value: CalibrationProgress) -> object:
            return (
                value.kind, tuple(spec.dedupe_key() for spec in value.specs),
                value.detected_opcodes, value.missing_events, value.issues,
                value.ready, value.retention.truncated,
            )
        if previous is not None and key(previous) == key(update):
            return
        if self.on_update is not None:
            self.in_callback.set()
            token = _callback_owner.set(self)
            try:
                returned = self.on_update(update)
                if inspect.isawaitable(returned):
                    # A wrapper can hide an async function from constructor
                    # validation. Do not silently leak its unawaited coroutine.
                    if inspect.iscoroutine(returned):
                        returned.close()
                    raise TypeError("on_update must not return an awaitable")
            except BaseException:
                self._callback_failed = True
                raise
            finally:
                _callback_owner.reset(token)
                self.in_callback.clear()

    def _assess(self) -> CalibrationProgress:
        session = self.session
        with session._retention_lock:
            frames = list(session._frames)
            retention = session._retention_unlocked()
        assessment = assess_frames(
            frames, item_id=session._item_id, quantity=session._quantity,
            action=session._action, context_frames=session._context_frames,
            min_confidence=session._min_confidence,
        )
        result = assessment.result
        issues = readiness_issues(result, session._action)
        issues += session._integrity_issues()
        if retention.truncated:
            issues += ("older calibration evidence was discarded; start a new session",)
        if assessment.error is not None:
            issues = (str(assessment.error), *issues)
        return CalibrationProgress(
            kind="progress", specs=result.specs,
            detected_opcodes=tuple(sorted({e.opcode for e in result.evidence}
                                         | {s.opcode for s in result.specs})),
            missing_events=required_events(session._action) - result.events_found,
            issues=issues, ready=not issues, retention=retention,
        )

    def _run(self) -> None:
        observed: tuple[int, tuple[str, ...]] | None = None
        try:
            while not self.cancelled.wait(self.INTERVAL):
                if self.requested.is_set():
                    self.finish("requested")
                    return
                if not self.enabled:
                    continue
                self.session.raise_if_failed()
                health = self.session._integrity_issues()
                revision = (self.session.frames_observed, health)
                if revision == observed:
                    continue
                update = self._assess()
                observed = (update.retention.frames_observed, health)
                if self.cancelled.is_set():
                    return
                self._emit(update)
                if self.requested.is_set():
                    self.finish("requested")
                    return
                if self.stop_on_complete and update.ready:
                    self._emit(replace(update, kind="finalizing"))
                    if not self.cancelled.is_set():
                        self.finish("complete")
                    return
        except BaseException as exc:
            self.session._record_error(exc)
            try:
                self.finish("error", discard=True)
            except BaseException:
                # The session retains the original exception and cleanup owner.
                pass
            if self.enabled and self.session._capture is None:
                update = CalibrationProgress(
                    kind="finished", specs=(), detected_opcodes=(),
                    missing_events=required_events(self.session._action),
                    issues=(str(exc),), ready=False,
                    retention=self.session.retention,
                )
                # A failed callback is not invoked a second time. Polling the
                # latest progress and wait()/error still expose the failure.
                if self._callback_failed:
                    self.progress = update
                else:
                    try:
                        self._emit(update)
                    except BaseException:
                        pass

    def finish(self, reason: str, *, discard: bool = False) -> CalibrationResult | None:
        with self._finish_lock:
            self.finalizing.set()
            try:
                return self._finish(reason, discard=discard)
            finally:
                self.finalizing.clear()

    def _finish(self, reason: str, *, discard: bool) -> CalibrationResult | None:
        session = self.session
        if self.result is not None:
            return self.result
        try:
            if discard:
                with session._lifecycle_lock:
                    if session._capture is not None:
                        session._finish_capture()
                    self.stop_reason = reason
                    return None
            result = session._stop_and_calibrate()
            issues = readiness_issues(result, session._action) + session._integrity_issues()
            if result.retention.truncated:
                issues += ("older calibration evidence was discarded; start a new session",)
            if reason == "complete" and issues:
                raise CalibrationAuthorityError(
                    "calibration changed during finalization: " + "; ".join(issues)
                )
            self.stop_reason = reason
        except BaseException as exc:
            session._record_error(exc)
            self.stop_reason = "error"
            raise
        finally:
            # Failed cleanup must remain owned and retryable through stop().
            if session._capture is None and (discard or self.stop_reason == "error"):
                self.done.set()
        if self.enabled:
            update = CalibrationProgress(
                kind="finished", specs=result.specs,
                detected_opcodes=tuple(sorted({e.opcode for e in result.evidence}
                                             | {s.opcode for s in result.specs})),
                missing_events=required_events(session._action) - result.events_found,
                issues=issues, ready=not issues, retention=result.retention,
                result=result,
            )
            try:
                self._emit(update)
            except BaseException as exc:
                session._record_error(exc)
                self.result = None
                self.stop_reason = "error"
                self.done.set()
                raise
        self.result = result
        self.done.set()
        return result
