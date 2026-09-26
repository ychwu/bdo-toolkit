"""Cancellation-safe asyncio facade for passive Agris balance capture."""

from __future__ import annotations

import asyncio
import math
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import AsyncIterator, Callable

from bdo_toolkit._async_utils import (
    _await_preserving_future,
    _wait_ignoring_cancellation as _settle,
)
from bdo_toolkit._capture_options import LiveCaptureOptions
from bdo_toolkit._capture_runtime import CaptureEndpoint, _attach_cleanup_owner
from bdo_toolkit.profiles import OpcodeProfile
from ._calibration_models import AgrisCalibrationResult

from ._capture import AgrisCaptureHealth
from .models import AgrisBalance, AgrisDiscoveryOptions, AgrisStatus
from .session import LiveAgrisSession


_POLL_SLICE_SECONDS = 0.1


class AsyncLiveAgrisSession:
    """Single-use, single-consumer async Agris balance session.

    ``expected_maximum_points`` is required and validated by the synchronous
    owner before any capture resources are acquired. Optional profile decoding
    bypasses discovery without fallback; this wrapper never writes profiles. It publishes only
    observed balances, never inferred consumption or a starting balance.

    Cancelling a poll stops capture and retains any balance already removed by
    its worker so a subsequent poll can drain it without loss or reordering.
    """

    def __init__(
        self,
        *,
        expected_maximum_points: int,
        live_options: LiveCaptureOptions | None = None,
        discovery_options: AgrisDiscoveryOptions | None = None,
        capture_seconds: float | None = None,
        save_pcap: str | Path | None = None,
        profile: OpcodeProfile | None = None,
    ) -> None:
        self._session = LiveAgrisSession(
            expected_maximum_points=expected_maximum_points,
            live_options=live_options,
            discovery_options=discovery_options,
            capture_seconds=capture_seconds,
            save_pcap=save_pcap,
            profile=profile,
        )
        # Reserve a worker for stop() even while a balance poll is in flight.
        self._executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="bdo-toolkit-agris-async"
        )
        self._executor_closed = False
        self._start_attempted = False
        self._start_complete = False
        self._poll_active = False
        self._pending_balance: AgrisBalance | None = None
        self._stop_future: asyncio.Future[None] | None = None

    @property
    def detection_mode(self) -> str:
        return self._session.detection_mode

    @property
    def calibration_result(self) -> AgrisCalibrationResult | None:
        return self._session.calibration_result

    @property
    def running(self) -> bool:
        return self._session.running

    @property
    def stopped(self) -> bool:
        return self._session.stopped

    @property
    def cleanup_incomplete(self) -> bool:
        return self._session.cleanup_incomplete

    @property
    def stop_reason(self) -> str | None:
        return self._session.stop_reason

    @property
    def error(self) -> BaseException | None:
        return self._session.error

    @property
    def endpoint(self) -> CaptureEndpoint | None:
        return self._session.endpoint

    @property
    def status(self) -> AgrisStatus:
        """Read the synchronous owner's current discovery authority."""

        return self._session.status

    @property
    def health(self) -> AgrisCaptureHealth:
        return self._session.health

    def raise_if_failed(self) -> None:
        self._session.raise_if_failed()

    def _submit[T](self, function: Callable[[], T]) -> asyncio.Future[T]:
        if self._executor_closed:
            raise RuntimeError("async live Agris session is already closed")
        return asyncio.get_running_loop().run_in_executor(self._executor, function)

    def _shutdown_executor(self) -> None:
        if not self._executor_closed:
            self._executor.shutdown(wait=False, cancel_futures=False)
            self._executor_closed = True

    def _ensure_stop_future(self) -> asyncio.Future[None]:
        if self._stop_future is None:
            self._stop_future = self._submit(self._session.stop)
        return self._stop_future

    def _after_cleanup(self, error: BaseException | None = None) -> None:
        if self.cleanup_incomplete:
            # Keep the executor and sync owner available for another stop().
            self._stop_future = None
            if error is not None:
                _attach_cleanup_owner(error, self, context="async Agris capture")
        else:
            self._shutdown_executor()

    async def start(self) -> None:
        """Wait for capture readiness without blocking the event loop."""

        if self._start_attempted:
            raise RuntimeError("async live Agris session was already started")
        self._start_attempted = True
        future = self._submit(self._session.start)
        try:
            await _await_preserving_future(future)
        except asyncio.CancelledError as exc:
            try:
                await _settle(future)
                self._start_complete = True
            except BaseException:
                pass
            if self._start_complete or self.cleanup_incomplete:
                self._start_complete = True
                try:
                    await _settle(self._ensure_stop_future())
                except BaseException:
                    pass
            self._after_cleanup(exc)
            raise
        except BaseException as exc:
            if self.cleanup_incomplete:
                self._start_complete = True
            self._after_cleanup(exc)
            raise
        else:
            self._start_complete = True

    async def stop(self) -> None:
        """Stop capture and retain cleanup ownership if shutdown cannot finish."""

        if self.stopped:
            self._shutdown_executor()
            self.raise_if_failed()
            return
        if not self._start_complete:
            raise RuntimeError("live Agris session was not started")
        future = self._ensure_stop_future()
        try:
            await _await_preserving_future(future)
        except asyncio.CancelledError as exc:
            try:
                await _settle(future)
            except BaseException:
                pass
            self._after_cleanup(exc)
            raise
        except BaseException as exc:
            self._after_cleanup(exc)
            raise
        else:
            self._after_cleanup()

    async def poll(self, timeout: float | None = None) -> AgrisBalance | None:
        """Await one observed balance, timeout, or drained session.

        Active calls require a finite nonnegative timeout (or ``None``).
        Stopped calls ignore the timeout while draining already buffered data.
        Cancelling a poll is terminal: capture is stopped before cancellation
        escapes, and an already-dequeued balance is preserved for a later poll.
        """

        if self._poll_active:
            raise RuntimeError("async live Agris session supports one consumer")
        if not self._start_complete and not self.stopped:
            raise RuntimeError("live Agris session was not started")
        if not self.stopped and timeout is not None:
            if (
                isinstance(timeout, bool)
                or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout)
                or timeout < 0
            ):
                raise ValueError("timeout must be finite and nonnegative")
        self._poll_active = True
        try:
            self.raise_if_failed()
            if self._pending_balance is not None:
                balance: AgrisBalance | None = self._pending_balance
                self._pending_balance = None
                return balance
            if self.stopped:
                self._shutdown_executor()
                return self._session.poll(timeout=0)
            loop = asyncio.get_running_loop()
            deadline = None if timeout is None else loop.time() + timeout
            while True:
                if self.stopped:
                    self._shutdown_executor()
                    return self._session.poll(timeout=0)
                remaining = None if deadline is None else max(0.0, deadline - loop.time())
                interval = (
                    _POLL_SLICE_SECONDS
                    if remaining is None
                    else min(_POLL_SLICE_SECONDS, remaining)
                )
                # A short slice also guarantees cancellation can collect the
                # in-flight result after a failed native stop, without waiting
                # forever for a blocking sync poll(None) to be woken.
                future = self._submit(partial(self._session.poll, interval))
                try:
                    balance = await _await_preserving_future(future)
                except asyncio.CancelledError as exc:
                    try:
                        await _settle(self._ensure_stop_future())
                    except BaseException:
                        pass
                    try:
                        self._pending_balance = await _settle(future)
                    except BaseException:
                        pass
                    self._after_cleanup(exc)
                    raise
                except BaseException:
                    if self.stopped and not self.cleanup_incomplete:
                        self._shutdown_executor()
                    raise
                self.raise_if_failed()
                if self.stopped and not self.cleanup_incomplete:
                    self._shutdown_executor()
                if balance is not None:
                    return balance
                if self.stopped:
                    # Stop may have finalized a tail immediately after this
                    # slice timed out. Drain it before declaring end-of-stream.
                    return self._session.poll(timeout=0)
                if deadline is not None and loop.time() >= deadline:
                    return None
        finally:
            self._poll_active = False

    async def events(self) -> AsyncIterator[AgrisBalance]:
        """Yield balances in observation order until stopped and drained."""

        while True:
            balance = await self.poll()
            if balance is None:
                return
            yield balance

    def __aiter__(self) -> AsyncIterator[AgrisBalance]:
        return self.events()

    async def __aenter__(self) -> AsyncLiveAgrisSession:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            await self.stop()
        except BaseException as cleanup_error:
            if exc_value is None:
                raise
            if self.cleanup_incomplete:
                _attach_cleanup_owner(
                    exc_value, self, context="async Agris context"
                )
            exc_value.add_note(
                f"async Agris context cleanup also failed: {cleanup_error!r}"
            )
