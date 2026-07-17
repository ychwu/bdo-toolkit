"""Asyncio facades for the synchronous live session APIs.

The packet capture, decoding, buffering, calibration, and shutdown logic stays
in :class:`LiveCaptureSession` and :class:`CalibrationSession`.  These wrappers
only move their blocking lifecycle operations off the asyncio event-loop
thread and make cancellation deterministic.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import AsyncIterator, Callable, Optional, TypeVar

from ._capture_options import LiveCaptureOptions, PacketCaptureOptions
from .calibration import CalibrationResult, CalibrationSession
from .capture import LiveCaptureSession
from .events import BDOEvent
from .filters import EventFilter
from .origin_learning import CompanionObservation


T = TypeVar("T")


async def _wait_ignoring_cancellation(future: asyncio.Future[T]) -> T:
    """Wait for an already-started operation, even after caller cancellation."""

    while not future.done():
        try:
            await asyncio.shield(future)
        except asyncio.CancelledError:
            # Cleanup must settle before the original cancellation escapes.
            continue
    return future.result()


def _thread_task(function: Callable[[], T]) -> asyncio.Task[T]:
    return asyncio.create_task(asyncio.to_thread(function))


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
        self._start_complete = False

    @property
    def running(self) -> bool:
        return self._session.running

    @property
    def stopped(self) -> bool:
        return self._session.stopped

    @property
    def stop_reason(self) -> Optional[str]:
        return self._session.stop_reason

    @property
    def error(self) -> Optional[BaseException]:
        return self._session.error

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

    async def start(self) -> None:
        """Start capture without blocking the asyncio event loop."""

        start_future = self._submit(self._session.start)
        try:
            await asyncio.shield(start_future)
        except asyncio.CancelledError:
            started = False
            try:
                await _wait_ignoring_cancellation(start_future)
                started = True
            except BaseException:
                # Cancellation remains the caller-visible outcome.
                pass
            if started:
                try:
                    stop_future = self._ensure_stop_future()
                    await _wait_ignoring_cancellation(stop_future)
                except BaseException:
                    pass
            self._shutdown_executor()
            raise
        except BaseException:
            # A failed startup never enters an async context, so close the
            # wrapper-owned executor here instead of relying on object GC.
            self._shutdown_executor()
            raise
        else:
            self._start_complete = True

    async def stop(self) -> None:
        """Gracefully stop capture and finish decoder/origin state."""

        if self._session.stopped:
            self._shutdown_executor()
            return
        if not self._start_complete:
            raise RuntimeError("live capture session was not started")

        stop_future = self._ensure_stop_future()
        try:
            await asyncio.shield(stop_future)
        except asyncio.CancelledError:
            try:
                try:
                    await _wait_ignoring_cancellation(stop_future)
                except BaseException:
                    # Cancellation remains the caller-visible outcome.
                    pass
            finally:
                self._shutdown_executor()
            raise
        except BaseException:
            if self._session.stopped:
                self._shutdown_executor()
            else:
                self._stop_future = None
            raise
        else:
            self._shutdown_executor()

    async def poll(self, timeout: Optional[float] = None) -> Optional[BDOEvent]:
        """Await one event, a timeout, or the fully drained stopped session.

        Cancelling a pending poll is terminal for this single-consumer session:
        capture is stopped before ``CancelledError`` is re-raised.
        """

        if self._poll_active:
            raise RuntimeError("async live capture session supports one consumer")
        if not self._start_complete and not self._session.stopped:
            raise RuntimeError("live capture session was not started")

        self._poll_active = True
        try:
            if self._session.stopped:
                # After stop(), finalization is complete and a zero-time poll
                # only drains already-buffered events; it cannot block.
                return self._session.poll(timeout=0)

            poll_future = self._submit(partial(self._session.poll, timeout))
            try:
                event = await asyncio.shield(poll_future)
            except asyncio.CancelledError:
                try:
                    stop_future = self._ensure_stop_future()
                    await _wait_ignoring_cancellation(stop_future)
                except BaseException:
                    pass
                try:
                    await _wait_ignoring_cancellation(poll_future)
                except BaseException:
                    pass
                self._shutdown_executor()
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
        """Yield events until capture stops and finalized events are drained."""

        while True:
            event = await self.poll()
            if event is None:
                return
            yield event

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
        if not self._session.stopped:
            await self.stop()
        else:
            self._shutdown_executor()


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
    ) -> None:
        self._session = CalibrationSession(
            item_id=item_id,
            quantity=quantity,
            action=action,
            capture_options=capture_options,
            context_frames=context_frames,
            min_confidence=min_confidence,
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
    def frames_collected(self) -> int:
        return self._session.frames_collected

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
            await asyncio.shield(start_task)
        except asyncio.CancelledError:
            started = False
            try:
                await _wait_ignoring_cancellation(start_task)
                started = True
            except BaseException:
                pass
            if started:
                abort_task = _thread_task(
                    partial(self._session.__exit__, None, None, None)
                )
                try:
                    await _wait_ignoring_cancellation(abort_task)
                except BaseException:
                    pass
            raise

        self._active = True
        self._terminal_action = None
        self._stop_task = None
        self._abort_task = None
        self._result = None

    async def _finish(self) -> CalibrationResult:
        try:
            result = await asyncio.to_thread(self._session.stop)
            self._result = result
            return result
        finally:
            self._active = False

    async def stop(self) -> CalibrationResult:
        """Stop capture, run calibration, and return its result."""

        if self._terminal_action == "abort":
            raise RuntimeError("calibration session was aborted")
        if not self._active and self._stop_task is None:
            raise RuntimeError("calibration session was not started")

        if self._stop_task is None:
            self._terminal_action = "stop"
            self._stop_task = asyncio.create_task(self._finish())

        try:
            return await asyncio.shield(self._stop_task)
        except asyncio.CancelledError:
            try:
                await _wait_ignoring_cancellation(self._stop_task)
            except BaseException:
                pass
            raise

    async def _discard(self) -> None:
        try:
            await asyncio.to_thread(self._session.__exit__, None, None, None)
        finally:
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

        try:
            await asyncio.shield(self._abort_task)
        except asyncio.CancelledError:
            try:
                await _wait_ignoring_cancellation(self._abort_task)
            except BaseException:
                pass
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
        if self._terminal_action == "stop":
            await self.stop()
        elif self._active:
            await self.abort()
