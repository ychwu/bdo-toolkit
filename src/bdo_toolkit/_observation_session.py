"""Private bounded observation-session lifecycle shared by Agris and solo XP."""
from __future__ import annotations

from collections.abc import Iterator
import math
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread, current_thread
import time
from types import TracebackType
from typing import Any, Callable, Self

from ._capture_options import LiveCaptureOptions
from ._capture_runtime import CaptureEndpoint, CaptureStats, LivePacketCapture, _attach_cleanup_owner
from ._reassembly import FlowManager
from .capture import CaptureIntegrityError


class ObservationSession[T, S]:
    """Single owner for acquisition, bounded delivery, deadlines and cleanup.

    Domains own their decoder, status/health view and clean-stop result policy.
    Factories are explicit so existing domain test seams remain unchanged.
    """

    _JOIN_TIMEOUT = 15.0
    _START_TIMEOUT = 15.0

    def __init__(self, *, label: str, snapshot: Callable[[], S],
                 manager: FlowManager, refresh: Callable[[float | None], None],
                 live_options: LiveCaptureOptions | None,
                 capture_seconds: float | None, save_pcap: str | Path | None,
                 capture_factory: Callable[..., LivePacketCapture],
                 handler_factory: Callable[..., Callable[[object], None]],
                 writer_factory: Callable[..., Any]) -> None:
        if live_options is not None and not isinstance(live_options, LiveCaptureOptions):
            raise TypeError("live_options must be LiveCaptureOptions or None")
        if capture_seconds is not None and (isinstance(capture_seconds, bool)
                or not isinstance(capture_seconds, (float, int))
                or not math.isfinite(capture_seconds) or capture_seconds <= 0):
            raise ValueError("capture_seconds must be finite and positive")
        self._options = live_options or LiveCaptureOptions()
        self._label, self._snapshot, self._refresh = label, snapshot, refresh
        self._capture_factory, self._handler_factory, self._writer_factory = capture_factory, handler_factory, writer_factory
        self._events: Queue[T] = Queue(self._options.event_queue_size)
        self._packets: Queue[object] = Queue(self._options.packet_queue_size)
        self._manager = manager
        self._status = snapshot()
        self._seconds = capture_seconds
        self._save_path = Path(save_pcap).expanduser().resolve() if save_pcap is not None else None
        if self._save_path is not None and self._save_path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError("save_pcap must end in .pcap or .pcapng")
        self._state_lock = Lock()
        self._lifecycle_lock = Lock()
        self._consumer_lock = Lock()
        self._stop_requested = Event()
        self._ready = Event()
        self._worker_done = Event()
        self._stopped = Event()
        self._worker: Thread | None = None
        self._capture: LivePacketCapture | None = None
        self._capture_started = False
        self._start_attempted = False
        self._cleanup_incomplete = False
        self._handler: Callable[[object], None] | None = None
        self._writer: Any = None
        self._stats = CaptureStats()
        self._error: BaseException | None = None
        self._stop_reason: str | None = None
        self._accepted = self._processed = self._packet_overflows = self._event_overflows = 0

    def _on_clean_stop(self) -> None:
        pass

    @property
    def endpoint(self) -> CaptureEndpoint | None:
        return self._capture.endpoint if self._capture is not None else None

    @property
    def running(self) -> bool:
        return self._ready.is_set() and not self._worker_done.is_set() and self.error is None

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    @property
    def cleanup_incomplete(self) -> bool:
        with self._state_lock:
            return self._cleanup_incomplete

    @property
    def error(self) -> BaseException | None:
        with self._state_lock:
            return self._error

    @property
    def stop_reason(self) -> str | None:
        with self._state_lock:
            return self._stop_reason

    def _record_error(self, error: BaseException) -> None:
        with self._state_lock:
            if self._error is None:
                self._error = error
            self._stop_reason = "error"
        self._stop_requested.set()

    def raise_if_failed(self) -> None:
        error = self.error
        if error is not None:
            raise error

    def _accept(self, packet: object) -> None:
        if self._stop_requested.is_set():
            return
        try:
            self._packets.put_nowait(packet)
        except Full:
            with self._state_lock:
                self._packet_overflows += 1
            error = CaptureIntegrityError(f"{self._label} packet queue overflow; capture incomplete")
            self._record_error(error)
            raise error
        with self._state_lock:
            self._accepted += 1

    def _publish(self, balance: T) -> None:
        try:
            self._events.put_nowait(balance)
        except Full as exc:
            with self._state_lock:
                self._event_overflows += 1
            raise CaptureIntegrityError(f"{self._label} balance queue overflow; consumer too slow") from exc

    def _update_status(self) -> None:
        status = self._snapshot()
        with self._state_lock:
            self._status = status

    def _read_stats(self, *, final: bool = False) -> None:
        capture = self._capture
        if capture is None:
            return
        stats = capture.stats if final else capture.snapshot_stats()
        with self._state_lock:
            self._stats = stats
        if (stats.dropped or 0) > 0 or (stats.interface_dropped or 0) > 0:
            raise CaptureIntegrityError(f"{self._label} capture backend reported dropped packets")

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._start_attempted:
                raise RuntimeError(f"{self._label} sessions are single-use")
            self._start_attempted = True
            worker = Thread(target=self._run, name=f"bdo-toolkit-{self._label.lower()}", daemon=True)
            self._worker = worker
            try:
                worker.start()
            except BaseException as exc:
                self._record_error(exc)
                self._worker_done.set()
                self._stopped.set()
                raise
        try:
            if not self._ready.wait(self._START_TIMEOUT):
                raise TimeoutError(f"{self._label} capture startup did not become ready")
            self.raise_if_failed()
        except BaseException as primary:
            self._record_error(primary)
            self._stop_requested.set()
            try:
                self.stop()
            except BaseException as cleanup:
                if cleanup is not primary:
                    primary.add_note(f"{self._label} startup cleanup also failed: {cleanup!r}")
            if self.cleanup_incomplete:
                _attach_cleanup_owner(primary, self, context=f"{self._label} startup")
            raise

    def _process(self, packet: object) -> None:
        if self._writer is not None:
            self._writer.write(packet)
        # Keep raw accepted packets even when an earlier loss invalidated decode.
        if self.error is None:
            assert self._handler is not None
            self._handler(packet)
            self._refresh(None)
            self._update_status()
        with self._state_lock:
            self._processed += 1

    def _run(self) -> None:
        try:
            if self._save_path is not None:
                if self._save_path.exists():
                    raise FileExistsError(f"refusing to overwrite existing capture: {self._save_path}")
                self._save_path.parent.mkdir(parents=True, exist_ok=True)
                self._writer = self._writer_factory(self._save_path)
            self._handler = self._handler_factory(self._manager)
            self._capture = self._capture_factory(capture_options=self._options, on_packet=self._accept)
            self._capture.start()
            self._capture_started = True
            self._capture.raise_if_failed()
            self._ready.set()
            deadline = time.monotonic() + self._seconds if self._seconds is not None else None
            next_stats = 0.0
            while not self._stop_requested.is_set():
                self._capture.raise_if_failed()
                if not self._capture.running:
                    raise CaptureIntegrityError(f"{self._label} capture backend stopped unexpectedly")
                if deadline is not None and time.monotonic() >= deadline:
                    with self._state_lock:
                        self._stop_reason = "duration"
                    break
                if time.monotonic() >= next_stats:
                    self._read_stats()
                    next_stats = time.monotonic() + 1.0
                try:
                    packet = self._packets.get(timeout=0.05)
                except Empty:
                    # No dequeued packet is outstanding here. A queued backlog
                    # must never be treated as a wall-clock TCP gap.
                    if self._packets.empty():
                        now = time.time()
                        self._manager.service_gaps(now)
                        self._refresh(now)
                        self._update_status()
                else:
                    self._process(packet)
        except BaseException as exc:
            self._record_error(exc)
        finally:
            self._stop_requested.set()
            try:
                self._shutdown()
            except BaseException as exc:
                self._record_error(exc)
            self._ready.set()  # Unblocks failed startup with its original error.
            self._worker_done.set()

    def _shutdown(self) -> None:
        capture = self._capture
        if capture is not None:
            try:
                if not capture.stopped and (self._capture_started or capture.cleanup_incomplete):
                    capture.stop()
                capture.raise_if_failed()
            except BaseException as exc:
                self._record_error(exc)
            incomplete = capture.cleanup_incomplete or (self._capture_started and not capture.stopped)
            if incomplete:
                with self._state_lock:
                    self._cleanup_incomplete = True
                self._record_error(RuntimeError(f"{self._label} native cleanup is incomplete; retry stop()"))
                return
            try:
                self._read_stats(final=True)
            except BaseException as exc:
                self._record_error(exc)
        while True:
            try:
                packet = self._packets.get_nowait()
            except Empty:
                break
            try:
                self._process(packet)
            except BaseException as exc:
                self._record_error(exc)
        if self.error is None:
            try:
                self._manager.finish()
            except BaseException as exc:
                self._record_error(exc)
        self._update_status()
        if self._writer is not None:
            try:
                self._writer.close()
            except BaseException as exc:
                self._record_error(exc)
                with self._state_lock:
                    self._cleanup_incomplete = True
                return
            self._writer = None
        with self._state_lock:
            self._cleanup_incomplete = False
            self._stop_reason = self._stop_reason or "requested"
        if self.error is None:
            self._on_clean_stop()
        self._stopped.set()

    def stop(self) -> None:
        if not self._start_attempted:
            raise RuntimeError(f"{self._label} session was not started")
        if self._worker is current_thread():
            raise RuntimeError(f"{self._label} stop() cannot join its decoder thread")
        self._stop_requested.set()
        with self._lifecycle_lock:
            worker = self._worker
            if worker is not None and worker.is_alive():
                worker.join(self._JOIN_TIMEOUT)
            if worker is not None and worker.is_alive():
                with self._state_lock:
                    self._cleanup_incomplete = True
                self._record_error(RuntimeError(f"{self._label} decoder cleanup timed out; retry stop()"))
            elif self.cleanup_incomplete:
                self._shutdown()
            error = self.error
            if error is not None:
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(error, self, context=f"{self._label} stop")
                raise error

    def poll(self, timeout: float | None = None) -> T | None:
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (float, int))
                                    or not math.isfinite(timeout) or timeout < 0):
            raise ValueError("timeout must be finite and nonnegative")
        if not self._start_attempted:
            raise RuntimeError(f"{self._label} session was not started")
        if not self._consumer_lock.acquire(blocking=False):
            raise RuntimeError(f"{self._label} sessions support one balance consumer")
        try:
            deadline = None if timeout is None else time.monotonic() + timeout
            while True:
                self.raise_if_failed()
                try:
                    balance = self._events.get_nowait()
                except Empty:
                    pass
                else:
                    self.raise_if_failed()
                    return balance
                if self.stopped:
                    return None
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return None
                try:
                    balance = self._events.get(timeout=min(0.05, remaining) if remaining is not None else 0.05)
                except Empty:
                    pass
                else:
                    self.raise_if_failed()
                    return balance
        finally:
            self._consumer_lock.release()

    def events(self) -> Iterator[T]:
        while True:
            balance = self.poll()
            if balance is not None:
                yield balance
            elif self.stopped:
                return

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
                 traceback: TracebackType | None) -> None:
        try:
            self.stop()
        except BaseException as cleanup:
            if exc_value is None:
                raise
            if self.cleanup_incomplete:
                _attach_cleanup_owner(exc_value, self, context=f"{self._label} context")
            exc_value.add_note(f"{self._label} context cleanup also failed: {cleanup!r}")
