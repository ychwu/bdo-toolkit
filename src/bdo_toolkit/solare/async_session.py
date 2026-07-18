"""Asyncio facade for the synchronous Solare live session."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from types import TracebackType
from typing import AsyncIterator, Callable, Optional, TypeVar

from bdo_toolkit._capture_options import PacketCaptureOptions
from ._constants import LIVE_CAPTURE_BUFFER_BYTES
from .models import SolareCaptureEndpoint, SolareCaptureResult, SolareUpdate
from .session import LiveSolareSession


T = TypeVar("T")


async def _settle(future: asyncio.Future[T]) -> T:
    while not future.done():
        try:
            await asyncio.shield(future)
        except asyncio.CancelledError:
            continue
    return future.result()


class AsyncLiveSolareSession:
    """Awaitable single-consumer facade over :class:`LiveSolareSession`."""

    def __init__(
        self,
        *,
        capture_options: Optional[PacketCaptureOptions] = None,
        save_pcap: str | Path | None = None,
        stop_on_complete: bool = True,
        on_update: Optional[Callable[[SolareUpdate], None]] = None,
        capture_buffer_bytes: int = LIVE_CAPTURE_BUFFER_BYTES,
    ) -> None:
        self._session = LiveSolareSession(
            capture_options=capture_options,
            save_pcap=save_pcap,
            stop_on_complete=stop_on_complete,
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
        self._stop_future: Optional[asyncio.Future[SolareCaptureResult]] = None

    @property
    def running(self) -> bool:
        return self._session.running

    @property
    def stopped(self) -> bool:
        return self._session.stopped

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

    def _submit(self, function: Callable[[], T]) -> asyncio.Future[T]:
        if self._closed:
            raise RuntimeError("async live Solare session is already closed")
        return asyncio.get_running_loop().run_in_executor(self._executor, function)

    def _shutdown(self) -> None:
        if not self._closed:
            self._executor.shutdown(wait=False, cancel_futures=False)
            self._closed = True

    async def start(self) -> None:
        """Start capture without blocking the event-loop thread."""

        if self._started or self._start_active:
            raise RuntimeError("live Solare session was already started")
        self._start_active = True
        try:
            try:
                future = self._submit(self._session.start)
                await asyncio.shield(future)
            except asyncio.CancelledError:
                started = False
                try:
                    await _settle(future)
                    started = True
                except BaseException:
                    pass
                if started:
                    try:
                        await _settle(self._submit(self._session.stop))
                    except BaseException:
                        pass
                self._shutdown()
                raise
            except BaseException:
                self._shutdown()
                raise
            self._started = True
        finally:
            self._start_active = False

    def _ensure_stop_future(self) -> asyncio.Future[SolareCaptureResult]:
        if self._stop_future is None:
            self._stop_future = self._submit(self._session.stop)
        return self._stop_future

    async def stop(self) -> SolareCaptureResult:
        """Stop capture and return the structurally classified result."""

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
            result = await asyncio.shield(future)
        except asyncio.CancelledError:
            try:
                await _settle(future)
            except BaseException:
                pass
            self._shutdown()
            raise
        except BaseException:
            self._shutdown()
            raise
        self._shutdown()
        return result

    async def wait(
        self, timeout: Optional[float] = None
    ) -> Optional[SolareCaptureResult]:
        """Await automatic completion or a timeout."""

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
                result = await asyncio.shield(future)
            except asyncio.CancelledError:
                try:
                    stop_future = self._ensure_stop_future()
                    await _settle(stop_future)
                except BaseException:
                    pass
                try:
                    await _settle(future)
                except BaseException:
                    pass
                self._shutdown()
                raise
            except BaseException:
                if self._session.stopped or self._session.error is not None:
                    self._shutdown()
                raise
            if result is not None or self._session.stopped:
                self._shutdown()
            return result
        finally:
            self._wait_active = False

    async def poll(self, timeout: Optional[float] = None) -> Optional[SolareUpdate]:
        """Await one structured progress update."""

        if not self._started:
            raise RuntimeError("live Solare session was not started")
        if self._poll_active:
            raise RuntimeError("async live Solare session supports one consumer")
        self._poll_active = True
        try:
            if self._session.stopped:
                self._shutdown()
                return self._session.poll(timeout=0)
            future = self._submit(partial(self._session.poll, timeout))
            try:
                update = await asyncio.shield(future)
            except asyncio.CancelledError:
                try:
                    await _settle(self._ensure_stop_future())
                except BaseException:
                    pass
                try:
                    await _settle(future)
                except BaseException:
                    pass
                self._shutdown()
                raise
            except BaseException:
                if self._session.stopped or self._session.error is not None:
                    self._shutdown()
                raise
            if self._session.stopped:
                self._shutdown()
            return update
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
            if not self._session.stopped:
                await self.stop()
        finally:
            self._shutdown()
