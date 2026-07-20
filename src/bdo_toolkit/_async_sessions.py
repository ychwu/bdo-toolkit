"""Asyncio facades for the synchronous live session APIs.

The packet capture, decoding, buffering, calibration, and shutdown logic stays
in :class:`LiveCaptureSession` and :class:`CalibrationSession`.  These wrappers
only move their blocking lifecycle operations off the asyncio event-loop
thread and make cancellation deterministic.
"""

from __future__ import annotations

import asyncio
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import AsyncIterator, Callable, Optional, TypeVar

from ._capture_runtime import CaptureEndpoint, _attach_cleanup_owner
from ._capture_options import LiveCaptureOptions, PacketCaptureOptions
from .calibration import (
    DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
    CalibrationResult,
    CalibrationRetention,
    CalibrationSession,
)
from .capture import LiveCaptureHealth, LiveCaptureSession, _validate_poll_timeout
from .events import BDOEvent
from .filters import EventFilter
from .origin_learning import CompanionObservation


T = TypeVar("T")
_ASYNC_EVENT_BATCH_SIZE = 64


@dataclass(frozen=True, slots=True)
class _EventBatch:
    """Events removed from the sync session and any error found after them."""

    events: tuple[BDOEvent, ...]
    terminal_error: BaseException | None = None


async def _wait_ignoring_cancellation(future: asyncio.Future[T]) -> T:
    """Wait for an already-started operation, even after caller cancellation."""

    while not future.done():
        try:
            # asyncio.wait() never propagates cancellation into ``future`` and
            # does not create a cancelled shield wrapper that may later log an
            # otherwise-retrieved worker exception on Python 3.14.
            await asyncio.wait((future,))
        except asyncio.CancelledError:
            # Cleanup must settle before the original cancellation escapes.
            continue
    return future.result()


async def _await_preserving_future(future: asyncio.Future[T]) -> T:
    """Await without cancelling or wrapping the submitted worker future."""

    await asyncio.wait((future,))
    return future.result()


def _thread_task(function: Callable[[], T]) -> asyncio.Task[T]:
    return asyncio.create_task(asyncio.to_thread(function))


def _poll_event_batch(
    session: LiveCaptureSession,
    max_items: int = _ASYNC_EVENT_BATCH_SIZE,
    *,
    block: bool = True,
) -> _EventBatch:
    """Block for one event, then drain an immediately available small batch."""

    first = session.poll(timeout=None if block else 0)
    if first is None:
        return _EventBatch(())
    events = [first]
    while len(events) < max_items:
        try:
            event = session.poll(timeout=0)
        except BaseException as exc:
            # A stopped synchronous session reports its retained background
            # error only after all queued/tail events have drained. Preserve
            # the events already removed by this batch and defer that error
            # until the async facade has delivered them too.
            return _EventBatch(tuple(events), terminal_error=exc)
        if event is None:
            break
        events.append(event)
    return _EventBatch(tuple(events))


class AsyncLiveCaptureSession:
    """Awaitable facade over :class:`LiveCaptureSession`.

    The underlying synchronous session remains the sole owner of capture,
    event ordering, bounded buffering, finalization, and background errors.
    A session is single-use and supports one event consumer.
    """

    def __init__(
        self,
        *,
        opcode_profile: str | Path | None = None,
        live_options: Optional[LiveCaptureOptions] = None,
        event_filter: Optional[EventFilter] = None,
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
    ) -> None:
        self._session = LiveCaptureSession(
            opcode_profile=opcode_profile,
            live_options=live_options,
            event_filter=event_filter,
            origin_observer=origin_observer,
        )
        # A pending blocking poll needs a second worker so stop() can wake it,
        # even when the host app configured a one-thread default executor.
        self._executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="bdo-toolkit-live",
        )
        self._executor_closed = False
        self._stop_future: asyncio.Future[None] | None = None
        self._poll_active = False
        # Batch-prefetched events belong to the session, not to an individual
        # async-generator frame. This keeps them reachable after an early
        # break, aclose(), cancellation, or a handoff to poll().
        self._pending_events: deque[BDOEvent] = deque()
        self._pending_error: BaseException | None = None
        self._start_attempted = False
        self._start_complete = False

    @property
    def running(self) -> bool:
        return self._session.running

    @property
    def stopped(self) -> bool:
        return self._session.stopped

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether synchronous capture cleanup remains retryable."""

        return self._session.cleanup_incomplete

    @property
    def stop_reason(self) -> Optional[str]:
        return self._session.stop_reason

    @property
    def error(self) -> Optional[BaseException]:
        return self._session.error

    @property
    def endpoint(self) -> Optional[CaptureEndpoint]:
        return self._session.endpoint

    @property
    def health(self) -> LiveCaptureHealth:
        return self._session.health

    def raise_if_failed(self) -> None:
        """Re-raise a retained background capture failure."""

        self._session.raise_if_failed()

    def _submit(self, function: Callable[[], T]) -> asyncio.Future[T]:
        if self._executor_closed:
            raise RuntimeError("async live capture session is already closed")
        loop = asyncio.get_running_loop()
        return loop.run_in_executor(self._executor, function)

    def _shutdown_executor(self) -> None:
        if self._executor_closed:
            return
        self._executor.shutdown(wait=False, cancel_futures=False)
        self._executor_closed = True

    def _ensure_stop_future(self) -> asyncio.Future[None]:
        if self._stop_future is None:
            self._stop_future = self._submit(self._session.stop)
        return self._stop_future

    def _inside_origin_observer(self) -> bool:
        predicate = getattr(self._session, "_inside_origin_observer", None)
        return bool(predicate is not None and predicate())

    def _accept_event_batch(self, batch: _EventBatch) -> None:
        """Take ownership of every result removed by a worker batch poll."""

        self._pending_events.extend(batch.events)
        if batch.terminal_error is not None and self._pending_error is None:
            self._pending_error = batch.terminal_error

    def _raise_pending_error(self) -> None:
        if self._pending_error is not None:
            raise self._pending_error

    async def start(self) -> None:
        """Start capture without blocking the asyncio event loop."""

        # Reject repeat/concurrent starts before submitting work.  In
        # particular, a rejected second start must not close the executor that
        # still owns a running first session and its eventual cleanup.
        if self._start_attempted:
            raise RuntimeError("async live capture session was already started")
        self._start_attempted = True
        start_future = self._submit(self._session.start)
        try:
            await _await_preserving_future(start_future)
        except asyncio.CancelledError as exc:
            started = False
            stop_future: asyncio.Future[None] | None = None
            try:
                await _wait_ignoring_cancellation(start_future)
                started = True
            except BaseException:
                # Cancellation remains the caller-visible outcome.
                pass
            if started or self._session.cleanup_incomplete:
                self._start_complete = True
                try:
                    stop_future = self._ensure_stop_future()
                    await _wait_ignoring_cancellation(stop_future)
                except BaseException:
                    pass
            if not self._session.cleanup_incomplete:
                self._shutdown_executor()
            else:
                if stop_future is not None and self._stop_future is stop_future:
                    self._stop_future = None
                _attach_cleanup_owner(
                    exc,
                    self,
                    context="async live item capture startup",
                )
            raise
        except BaseException as exc:
            # A failed startup never enters an async context, so close the
            # wrapper-owned executor unless the sync session retained a live
            # backend specifically so cleanup can be retried.
            if self._session.cleanup_incomplete:
                self._start_complete = True
                _attach_cleanup_owner(
                    exc,
                    self,
                    context="async live item capture startup",
                )
            else:
                self._shutdown_executor()
            raise
        else:
            self._start_complete = True

    async def stop(self) -> None:
        """Gracefully stop capture and finish decoder/origin state."""

        if self._inside_origin_observer():
            raise RuntimeError(
                "stop() cannot block inside the live decoder or origin "
                "observer; use request_stop() instead"
            )
        if self._session.stopped:
            self._shutdown_executor()
            return
        if not self._start_complete:
            raise RuntimeError("live capture session was not started")

        stop_future = self._ensure_stop_future()
        try:
            await _await_preserving_future(stop_future)
        except asyncio.CancelledError:
            try:
                try:
                    await _wait_ignoring_cancellation(stop_future)
                except BaseException:
                    # Cancellation remains the caller-visible outcome.
                    pass
            finally:
                if not self._session.cleanup_incomplete:
                    self._shutdown_executor()
                else:
                    if self._stop_future is stop_future:
                        self._stop_future = None
            raise
        except BaseException:
            if self._session.stopped:
                self._shutdown_executor()
            else:
                if self._stop_future is stop_future:
                    self._stop_future = None
            raise
        else:
            self._shutdown_executor()

    def request_stop(self) -> None:
        """Request callback-safe shutdown without blocking its worker thread."""

        self._session.request_stop()

    async def poll(self, timeout: Optional[float] = None) -> Optional[BDOEvent]:
        """Await one event, a timeout, or the fully drained stopped session.

        Cancelling a pending poll is terminal for this single-consumer session:
        capture is stopped before ``CancelledError`` is re-raised.
        """

        if self._inside_origin_observer():
            raise RuntimeError(
                "poll() cannot consume events inside origin_observer; "
                "consume them after the callback returns"
            )
        if self._poll_active:
            raise RuntimeError("async live capture session supports one consumer")
        if not self._start_complete and not self._session.stopped:
            raise RuntimeError("live capture session was not started")
        # Session-owned prefetch and the stopped fast path must not bypass the
        # synchronous API's timeout validation contract.
        _validate_poll_timeout(timeout)

        self._poll_active = True
        try:
            if self._session.stopped:
                self._shutdown_executor()
            if self._pending_events:
                return self._pending_events.popleft()
            self._raise_pending_error()

            if self._session.stopped:
                # After stop(), finalization is complete and a zero-time poll
                # only drains already-buffered events; it cannot block.
                return self._session.poll(timeout=0)

            poll_future = self._submit(partial(self._session.poll, timeout))
            try:
                event = await _await_preserving_future(poll_future)
            except asyncio.CancelledError:
                stop_future: asyncio.Future[None] | None = None
                try:
                    stop_future = self._ensure_stop_future()
                    await _wait_ignoring_cancellation(stop_future)
                except BaseException:
                    pass
                try:
                    event = await _wait_ignoring_cancellation(poll_future)
                except BaseException:
                    pass
                else:
                    if event is not None:
                        self._pending_events.append(event)
                if not self._session.cleanup_incomplete:
                    self._shutdown_executor()
                else:
                    if (
                        stop_future is not None
                        and self._stop_future is stop_future
                    ):
                        self._stop_future = None
                raise
            except BaseException:
                if self._session.stopped:
                    self._shutdown_executor()
                raise

            if self._session.stopped:
                self._shutdown_executor()
            return event
        finally:
            self._poll_active = False

    async def events(self) -> AsyncIterator[BDOEvent]:
        """Yield events in order until capture stops and final events drain.

        The blocking bridge fetches up to 64 immediately available events per
        executor submission. Individual :meth:`poll` calls retain their
        one-event semantics for UI and timeout-driven consumers.
        """

        if self._inside_origin_observer():
            raise RuntimeError(
                "events() cannot consume events inside origin_observer; "
                "consume them after the callback returns"
            )
        while True:
            if self._pending_events:
                yield self._pending_events.popleft()
                continue
            await self._fill_pending_events()
            if not self._pending_events:
                return

    async def _fill_pending_events(self) -> None:
        if self._inside_origin_observer():
            raise RuntimeError(
                "events() cannot consume events inside origin_observer; "
                "consume them after the callback returns"
            )
        if self._poll_active:
            raise RuntimeError("async live capture session supports one consumer")
        if not self._start_complete and not self._session.stopped:
            raise RuntimeError("live capture session was not started")

        self._poll_active = True
        try:
            if self._pending_events:
                return
            self._raise_pending_error()

            if self._session.stopped:
                self._shutdown_executor()
                self._accept_event_batch(
                    _poll_event_batch(self._session, block=False)
                )
                return

            poll_future = self._submit(partial(_poll_event_batch, self._session))
            try:
                batch = await _await_preserving_future(poll_future)
            except asyncio.CancelledError:
                stop_future: asyncio.Future[None] | None = None
                try:
                    stop_future = self._ensure_stop_future()
                    await _wait_ignoring_cancellation(stop_future)
                except BaseException:
                    pass
                try:
                    batch = await _wait_ignoring_cancellation(poll_future)
                except BaseException:
                    pass
                else:
                    self._accept_event_batch(batch)
                if not self._session.cleanup_incomplete:
                    self._shutdown_executor()
                else:
                    if (
                        stop_future is not None
                        and self._stop_future is stop_future
                    ):
                        self._stop_future = None
                raise
            except BaseException:
                if self._session.stopped:
                    self._shutdown_executor()
                raise

            self._accept_event_batch(batch)
            if self._session.stopped:
                self._shutdown_executor()
        finally:
            self._poll_active = False

    def __aiter__(self) -> AsyncIterator[BDOEvent]:
        return self.events()

    async def __aenter__(self) -> "AsyncLiveCaptureSession":
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if not self._session.stopped:
                await self.stop()
            else:
                self._shutdown_executor()
        except BaseException as cleanup_error:
            if exc_value is None:
                raise
            if self.cleanup_incomplete:
                _attach_cleanup_owner(
                    exc_value,
                    self,
                    context="async live item capture context",
                )
            if hasattr(exc_value, "add_note"):
                exc_value.add_note(
                    "async live item capture context cleanup also failed: "
                    f"{cleanup_error!r}"
                )


class AsyncCalibrationSession:
    """Awaitable facade over :class:`CalibrationSession`.

    ``stop()`` returns the same :class:`CalibrationResult` as the synchronous
    session.  Exiting the async context before ``stop()`` calls ``abort()`` and
    discards the unfinished calibration, matching the synchronous context
    manager's safety behavior.
    """

    def __init__(
        self,
        *,
        item_id: int,
        quantity: Optional[int] = None,
        action: str = "auto",
        capture_options: Optional[PacketCaptureOptions] = None,
        context_frames: int = 5,
        min_confidence: float = 0.80,
        max_retained_frames: int = DEFAULT_CALIBRATION_MAX_RETAINED_FRAMES,
        max_retained_bytes: int = DEFAULT_CALIBRATION_MAX_RETAINED_BYTES,
    ) -> None:
        self._session = CalibrationSession(
            item_id=item_id,
            quantity=quantity,
            action=action,
            capture_options=capture_options,
            context_frames=context_frames,
            min_confidence=min_confidence,
            max_retained_frames=max_retained_frames,
            max_retained_bytes=max_retained_bytes,
        )
        self._active = False
        self._terminal_action: str | None = None
        self._stop_task: asyncio.Task[CalibrationResult] | None = None
        self._abort_task: asyncio.Task[None] | None = None
        self._result: CalibrationResult | None = None

    @property
    def running(self) -> bool:
        return self._session.running

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether calibration cleanup remains owned for another attempt."""

        return self._session.cleanup_incomplete

    @property
    def frames_collected(self) -> int:
        return self._session.frames_collected

    @property
    def frames_observed(self) -> int:
        return self._session.frames_observed

    @property
    def frames_retained(self) -> int:
        return self._session.frames_retained

    @property
    def frames_discarded(self) -> int:
        return self._session.frames_discarded

    @property
    def bytes_observed(self) -> int:
        return self._session.bytes_observed

    @property
    def bytes_retained(self) -> int:
        return self._session.bytes_retained

    @property
    def bytes_discarded(self) -> int:
        return self._session.bytes_discarded

    @property
    def retention_truncated(self) -> bool:
        return self._session.retention_truncated

    @property
    def retention(self) -> CalibrationRetention:
        return self._session.retention

    @property
    def result(self) -> CalibrationResult | None:
        """Completed result, including one preserved across cancellation."""

        return self._result

    async def start(self) -> None:
        """Begin calibration capture without blocking the event loop."""

        if self._active:
            raise RuntimeError("calibration session is already running")

        start_task = _thread_task(self._session.start)
        try:
            await _await_preserving_future(start_task)
        except asyncio.CancelledError as exc:
            started = False
            try:
                await _wait_ignoring_cancellation(start_task)
                started = True
            except BaseException:
                pass
            if started or self._session.cleanup_incomplete:
                # A late successful start belongs to a new calibration run.
                # Clear every terminal artifact from the prior run before
                # attempting cancellation cleanup, so an exposed cleanup
                # owner cannot return a stale result or reuse an old task.
                self._terminal_action = None
                self._stop_task = None
                self._abort_task = None
                self._result = None
                abort_task = _thread_task(
                    partial(self._session.__exit__, None, None, None)
                )
                try:
                    await _wait_ignoring_cancellation(abort_task)
                except BaseException:
                    pass
            if self._session.cleanup_incomplete:
                self._active = True
                _attach_cleanup_owner(
                    exc,
                    self,
                    context="async live calibration startup",
                )
            raise
        except BaseException as exc:
            if self._session.cleanup_incomplete:
                self._active = True
                self._terminal_action = None
                self._stop_task = None
                self._abort_task = None
                self._result = None
                _attach_cleanup_owner(
                    exc,
                    self,
                    context="async live calibration startup",
                )
            raise

        self._active = True
        self._terminal_action = None
        self._stop_task = None
        self._abort_task = None
        self._result = None

    async def _finish(self) -> CalibrationResult:
        try:
            result = await asyncio.to_thread(self._session.stop)
        except BaseException:
            self._active = self._session.cleanup_incomplete
            raise
        self._result = result
        self._active = False
        return result

    async def stop(self) -> CalibrationResult:
        """Stop capture, run calibration, and return its result."""

        if self._terminal_action == "abort":
            raise RuntimeError("calibration session was aborted")
        if not self._active and self._stop_task is None:
            raise RuntimeError("calibration session was not started")

        if self._stop_task is None:
            self._terminal_action = "stop"
            self._stop_task = asyncio.create_task(self._finish())
        stop_task = self._stop_task

        try:
            return await _await_preserving_future(stop_task)
        except asyncio.CancelledError:
            try:
                await _wait_ignoring_cancellation(stop_task)
            except BaseException:
                pass
            if self._session.cleanup_incomplete:
                if self._stop_task is stop_task:
                    self._stop_task = None
                self._active = True
            raise
        except BaseException:
            if self._session.cleanup_incomplete:
                if self._stop_task is stop_task:
                    self._stop_task = None
                self._active = True
            raise

    async def _discard(self) -> None:
        try:
            await asyncio.to_thread(self._session.__exit__, None, None, None)
        except BaseException:
            self._active = self._session.cleanup_incomplete
            raise
        else:
            self._active = False

    async def abort(self) -> None:
        """Stop capture and discard it without running calibration."""

        if self._terminal_action == "stop":
            await self.stop()
            return
        if not self._active and self._abort_task is None:
            return

        if self._abort_task is None:
            self._terminal_action = "abort"
            self._abort_task = asyncio.create_task(self._discard())
        abort_task = self._abort_task

        try:
            await _await_preserving_future(abort_task)
        except asyncio.CancelledError:
            try:
                await _wait_ignoring_cancellation(abort_task)
            except BaseException:
                pass
            if self._session.cleanup_incomplete:
                if self._abort_task is abort_task:
                    self._abort_task = None
                self._active = True
            raise
        except BaseException:
            if self._session.cleanup_incomplete:
                if self._abort_task is abort_task:
                    self._abort_task = None
                self._active = True
            raise

    async def __aenter__(self) -> "AsyncCalibrationSession":
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if self._terminal_action == "stop":
                await self.stop()
            elif self._active:
                await self.abort()
        except BaseException as cleanup_error:
            if exc_value is None:
                raise
            if self.cleanup_incomplete:
                _attach_cleanup_owner(
                    exc_value,
                    self,
                    context="async live calibration context",
                )
            if hasattr(exc_value, "add_note"):
                exc_value.add_note(
                    "async live calibration context cleanup also failed: "
                    f"{cleanup_error!r}"
                )
