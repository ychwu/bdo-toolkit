"""Asyncio facade for the synchronous Solare live session."""

from __future__ import annotations

import asyncio
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import AsyncIterator, Callable, Optional

from bdo_toolkit._capture_options import PacketCaptureOptions
from bdo_toolkit._capture_runtime import _attach_cleanup_owner
from ._constants import LIVE_CAPTURE_BUFFER_BYTES
from .models import (
    SolareCaptureEndpoint,
    SolareCaptureResult,
    SolareUpdate,
    SolareUpdateKind,
)
from .session import LiveSolareSession, _validate_timeout


async def _settle[T](future: asyncio.Future[T]) -> T:
    while not future.done():
        try:
            await asyncio.wait((future,))
        except asyncio.CancelledError:
            continue
    return future.result()


async def _await_preserving_future[T](future: asyncio.Future[T]) -> T:
    """Await a worker future without cancelling it or creating a shield."""

    await asyncio.wait((future,))
    return future.result()


class AsyncLiveSolareSession:
    """Awaitable single-consumer facade over :class:`LiveSolareSession`."""

    def __init__(
        self,
        *,
        capture_options: Optional[PacketCaptureOptions] = None,
        save_pcap: str | Path | None = None,
        stop_on_complete: bool = True,
        retain_raw_extensions: bool = False,
        on_update: Optional[Callable[[SolareUpdate], None]] = None,
        capture_buffer_bytes: int = LIVE_CAPTURE_BUFFER_BYTES,
    ) -> None:
        self._session = LiveSolareSession(
            capture_options=capture_options,
            save_pcap=save_pcap,
            stop_on_complete=stop_on_complete,
            retain_raw_extensions=retain_raw_extensions,
            on_update=on_update,
            capture_buffer_bytes=capture_buffer_bytes,
        )
        self._executor = ThreadPoolExecutor(
            # One progress poll and one completion wait may coexist. Keep a
            # third worker reserved so stop/cancellation can always wake both.
            max_workers=3,
            thread_name_prefix="bdo-toolkit-solare-async",
        )
        self._closed = False
        self._started = False
        self._start_active = False
        self._poll_active = False
        self._wait_active = False
        self._pending_updates: deque[SolareUpdate] = deque()
        self._stop_future: Optional[asyncio.Future[SolareCaptureResult]] = None
        self._terminal_shutdown_task: Optional[asyncio.Task[None]] = None

    @property
    def running(self) -> bool:
        return self._session.running

    @property
    def stopped(self) -> bool:
        return self._session.stopped

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether native capture cleanup remains owned for another attempt."""

        return self._session.cleanup_incomplete

    @property
    def result(self) -> Optional[SolareCaptureResult]:
        return self._session.result

    @property
    def error(self) -> Optional[BaseException]:
        return self._session.error

    @property
    def stop_reason(self) -> Optional[str]:
        return self._session.stop_reason

    @property
    def endpoint(self) -> Optional[SolareCaptureEndpoint]:
        return self._session.endpoint

    def raise_if_failed(self) -> None:
        self._session.raise_if_failed()

    def _submit[T](self, function: Callable[[], T]) -> asyncio.Future[T]:
        if self._closed:
            raise RuntimeError("async live Solare session is already closed")
        return asyncio.get_running_loop().run_in_executor(self._executor, function)

    def _shutdown(self) -> None:
        if not self._closed:
            self._executor.shutdown(wait=False, cancel_futures=False)
            self._closed = True

    def _schedule_terminal_shutdown(self) -> None:
        task = self._terminal_shutdown_task
        if task is not None and not task.done():
            return

        async def close_after_worker_and_calls_settle() -> None:
            while not self._session.stopped and not self._closed:
                await asyncio.sleep(0.01)
            while not self._closed and (
                self._start_active
                or self._poll_active
                or self._wait_active
                or (
                    self._stop_future is not None
                    and not self._stop_future.done()
                )
            ):
                await asyncio.sleep(0.01)
            self._shutdown()

        self._terminal_shutdown_task = asyncio.create_task(
            close_after_worker_and_calls_settle()
        )

    def _observe_polled_update(
        self,
        update: Optional[SolareUpdate],
    ) -> Optional[SolareUpdate]:
        if update is not None and update.kind is SolareUpdateKind.FINISHED:
            self._schedule_terminal_shutdown()
        elif self._session.stopped:
            self._shutdown()
        return update

    async def start(self) -> None:
        """Start capture without blocking the event-loop thread."""

        if self._started or self._start_active:
            raise RuntimeError("live Solare session was already started")
        self._start_active = True
        try:
            try:
                future = self._submit(self._session.start)
                await _await_preserving_future(future)
            except asyncio.CancelledError as exc:
                started = False
                stop_future: asyncio.Future[SolareCaptureResult] | None = None
                try:
                    await _settle(future)
                    started = True
                except BaseException:
                    pass
                if started or self._session.cleanup_incomplete:
                    self._started = True
                    try:
                        stop_future = self._ensure_stop_future()
                        await _settle(stop_future)
                    except BaseException:
                        pass
                if self._session.cleanup_incomplete:
                    if (
                        stop_future is not None
                        and self._stop_future is stop_future
                    ):
                        self._stop_future = None
                    _attach_cleanup_owner(
                        exc,
                        self,
                        context="async live Solare startup",
                    )
                else:
                    self._shutdown()
                raise
            except BaseException as exc:
                if self._session.cleanup_incomplete:
                    # The synchronous session deliberately retains the native
                    # callback owners so a later stop() can finish cleanup.
                    self._started = True
                    _attach_cleanup_owner(
                        exc,
                        self,
                        context="async live Solare startup",
                    )
                else:
                    self._shutdown()
                raise
            self._started = True
        finally:
            self._start_active = False

    def _ensure_stop_future(self) -> asyncio.Future[SolareCaptureResult]:
        if self._stop_future is None:
            self._stop_future = self._submit(self._session.stop)
        return self._stop_future

    def _inside_update_callback(self) -> bool:
        predicate = getattr(self._session, "_inside_update_callback", None)
        return bool(predicate is not None and predicate())

    async def stop(self) -> SolareCaptureResult:
        """Stop capture and return the structurally classified result."""

        if self._inside_update_callback():
            raise RuntimeError(
                "stop() cannot block inside on_update; use "
                "request_stop() instead"
            )
        if not self._started:
            raise RuntimeError("live Solare session was not started")
        if self._session.stopped:
            try:
                self._session.raise_if_failed()
                result = self._session.result
                if result is None:
                    raise RuntimeError(
                        "live Solare session stopped without a result"
                    )
                return result
            finally:
                self._shutdown()

        future = self._ensure_stop_future()
        try:
            result = await _await_preserving_future(future)
        except asyncio.CancelledError:
            try:
                await _settle(future)
            except BaseException:
                pass
            if self._session.cleanup_incomplete:
                if self._stop_future is future:
                    self._stop_future = None
            else:
                self._shutdown()
            raise
        except BaseException:
            if self._session.cleanup_incomplete:
                if self._stop_future is future:
                    self._stop_future = None
            else:
                self._shutdown()
            raise
        self._shutdown()
        return result

    def request_stop(self) -> None:
        """Request orderly shutdown without blocking the event loop."""

        ready_callback_active = self._start_active and self._session.running
        if not (self._started or ready_callback_active):
            raise RuntimeError("live Solare session was not started")
        self._session.request_stop()

    async def wait(
        self, timeout: Optional[float] = None
    ) -> Optional[SolareCaptureResult]:
        """Await automatic completion or a timeout.

        After completed stop, ``timeout`` is ignored and terminal state is
        returned immediately.
        """

        if self._inside_update_callback():
            raise RuntimeError(
                "wait() cannot block inside on_update; use request_stop() "
                "and wait after the callback returns"
            )
        if not self._started:
            raise RuntimeError("live Solare session was not started")
        if self._wait_active:
            raise RuntimeError("async live Solare session supports one waiter")
        self._wait_active = True
        try:
            if self._session.stopped:
                self._shutdown()
                return self._session.wait(timeout=0)
            future = self._submit(partial(self._session.wait, timeout))
            try:
                result = await _await_preserving_future(future)
            except asyncio.CancelledError:
                stop_future: asyncio.Future[SolareCaptureResult] | None = None
                try:
                    stop_future = self._ensure_stop_future()
                    await _settle(stop_future)
                except BaseException:
                    pass
                try:
                    await _settle(future)
                except BaseException:
                    pass
                if self._session.cleanup_incomplete:
                    if (
                        stop_future is not None
                        and self._stop_future is stop_future
                    ):
                        self._stop_future = None
                else:
                    self._shutdown()
                raise
            except BaseException:
                if (
                    not self._session.cleanup_incomplete
                    and (self._session.stopped or self._session.error is not None)
                ):
                    self._shutdown()
                raise
            if result is not None or self._session.stopped:
                self._shutdown()
            return result
        finally:
            self._wait_active = False

    async def poll(self, timeout: Optional[float] = None) -> Optional[SolareUpdate]:
        """Await one structured progress update.

        After completed stop, ``timeout`` is ignored while progress drains.
        """

        if self._inside_update_callback():
            raise RuntimeError(
                "poll() cannot consume updates inside on_update; consume "
                "them outside the callback"
            )
        if not self._started:
            raise RuntimeError("live Solare session was not started")
        if self._poll_active:
            raise RuntimeError("async live Solare session supports one consumer")
        stopped_at_entry = self._session.stopped
        if not stopped_at_entry:
            _validate_timeout(timeout, name="timeout")
        self._poll_active = True
        try:
            if self._pending_updates:
                return self._observe_polled_update(
                    self._pending_updates.popleft()
                )
            if self._session.stopped:
                self._shutdown()
                return self._session.poll(timeout=0)
            future = self._submit(partial(self._session.poll, timeout))
            try:
                update = await _await_preserving_future(future)
            except asyncio.CancelledError:
                stop_future: asyncio.Future[SolareCaptureResult] | None = None
                try:
                    stop_future = self._ensure_stop_future()
                    await _settle(stop_future)
                except BaseException:
                    pass
                try:
                    settled_update = await _settle(future)
                except BaseException:
                    pass
                else:
                    if settled_update is not None:
                        self._pending_updates.append(settled_update)
                if self._session.cleanup_incomplete:
                    if (
                        stop_future is not None
                        and self._stop_future is stop_future
                    ):
                        self._stop_future = None
                else:
                    self._shutdown()
                raise
            except BaseException:
                if (
                    not self._session.cleanup_incomplete
                    and (self._session.stopped or self._session.error is not None)
                ):
                    self._shutdown()
                raise
            return self._observe_polled_update(update)
        finally:
            self._poll_active = False

    async def updates(self) -> AsyncIterator[SolareUpdate]:
        while True:
            update = await self.poll()
            if update is None:
                return
            yield update

    def __aiter__(self) -> AsyncIterator[SolareUpdate]:
        return self.updates()

    async def __aenter__(self) -> "AsyncLiveSolareSession":
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if exc_value is None:
                await self.stop()
            else:
                try:
                    await self.stop()
                except BaseException as cleanup_error:
                    # Preserve the exception already escaping the async block.
                    if self.cleanup_incomplete:
                        _attach_cleanup_owner(
                            exc_value,
                            self,
                            context="async live Solare context",
                        )
                    exc_value.add_note(
                        "async live Solare context cleanup also failed: "
                        f"{cleanup_error!r}"
                    )
        finally:
            if not self._session.cleanup_incomplete:
                self._shutdown()
