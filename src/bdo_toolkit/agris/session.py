"""Single-owner live Agris acquisition; no implicit writes or consumption accounting."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
import math
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread, current_thread
import time
from types import TracebackType
from typing import Any, Callable

from .._capture_backend import make_packet_handler, open_packet_writer
from .._capture_options import LiveCaptureOptions
from .._capture_runtime import CaptureEndpoint, CaptureStats, LivePacketCapture, _attach_cleanup_owner
from ..capture import CaptureIntegrityError
from ..profiles import OpcodeProfile
from ._profile import profile_layout
from ._calibration_models import AgrisCalibrationResult, final_calibration_result
from ._capture import AgrisCaptureHealth, AgrisFlowManager
from ._discovery import AgrisTracker
from .models import AgrisBalance, AgrisDiscoveryOptions, AgrisStatus


class LiveAgrisSession:
    """Continuous, single-consumer Agris balance stream with required cap input.

    One owner thread starts/stops acquisition, decodes packets, and services
    deadlines even if the application stops polling. Native callbacks only
    enqueue packets. Both queues are bounded: overflow is an explicit failure.
    Omit profile for cold discovery, or supply a profile for strict saved-layout decoding.
    Sessions never write profiles or silently fall back to discovery.
    """

    _JOIN_TIMEOUT = 15.0
    _START_TIMEOUT = 15.0

    def __init__(self, *, expected_maximum_points: int,
                 live_options: LiveCaptureOptions | None = None,
                 discovery_options: AgrisDiscoveryOptions | None = None,
                 capture_seconds: float | None = None,
                 save_pcap: str | Path | None = None,
                 profile: OpcodeProfile | None = None) -> None:
        if live_options is not None and not isinstance(live_options, LiveCaptureOptions):
            raise TypeError("live_options must be LiveCaptureOptions or None")
        if capture_seconds is not None and (isinstance(capture_seconds, bool)
                or not isinstance(capture_seconds, (float, int))
                or not math.isfinite(capture_seconds) or capture_seconds <= 0):
            raise ValueError("capture_seconds must be finite and positive")
        self._options = live_options or LiveCaptureOptions()
        layout = profile_layout(profile)
        self._detection_mode = "profile" if layout is not None else "discovery"
        self._calibration_result: AgrisCalibrationResult | None = None
        self._events: Queue[AgrisBalance] = Queue(self._options.event_queue_size)
        self._packets: Queue[object] = Queue(self._options.packet_queue_size)
        self._tracker = AgrisTracker(expected_maximum_points=expected_maximum_points,
                                    options=discovery_options, on_balance=self._publish, profile_layout=layout)
        self._manager = AgrisFlowManager(self._tracker, self._options.ports, live=True)
        self._status = self._tracker.snapshot()
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

    @property
    def detection_mode(self) -> str:
        """Either profile decoding or cold discovery; never silently switched."""
        return self._detection_mode

    @property
    def calibration_result(self) -> AgrisCalibrationResult | None:
        """Final clean discovery evidence only; never available in profile mode."""
        return self._calibration_result if self.stopped and self.error is None else None

    @property
    def status(self) -> AgrisStatus:
        with self._state_lock:
            status, error = self._status, self._error
        return replace(status, status="invalid", balance=None, reason=str(error)) if error else status

    @property
    def health(self) -> AgrisCaptureHealth:
        with self._state_lock:
            return AgrisCaptureHealth(
                packets_processed=self._processed, packets_accepted=self._accepted,
                packet_queue_overflows=self._packet_overflows, event_queue_overflows=self._event_overflows,
                tcp_gap_resets=self._manager.tcp_gap_resets, flow_state_evictions=self._manager.evictions,
                pcap_received=self._stats.received, pcap_dropped=self._stats.dropped,
                pcap_interface_dropped=self._stats.interface_dropped,
                capture_buffer_bytes=self._stats.capture_buffer_bytes,
                cleanup_incomplete=self._cleanup_incomplete)

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
            error = CaptureIntegrityError("Agris packet queue overflow; capture incomplete")
            self._record_error(error)
            raise error
        with self._state_lock:
            self._accepted += 1

    def _publish(self, balance: AgrisBalance) -> None:
        try:
            self._events.put_nowait(balance)
        except Full as exc:
            with self._state_lock:
                self._event_overflows += 1
            raise CaptureIntegrityError("Agris balance queue overflow; consumer too slow") from exc

    def _update_status(self) -> None:
        status = self._tracker.snapshot()
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
            raise CaptureIntegrityError("Agris capture backend reported dropped packets")

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._start_attempted:
                raise RuntimeError("Agris sessions are single-use")
            self._start_attempted = True
            worker = Thread(target=self._run, name="bdo-toolkit-agris", daemon=True)
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
                raise TimeoutError("Agris capture startup did not become ready")
            self.raise_if_failed()
        except BaseException as primary:
            self._record_error(primary)
            self._stop_requested.set()
            try:
                self.stop()
            except BaseException as cleanup:
                if cleanup is not primary:
                    primary.add_note(f"Agris startup cleanup also failed: {cleanup!r}")
            if self.cleanup_incomplete:
                _attach_cleanup_owner(primary, self, context="Agris startup")
            raise

    def _process(self, packet: object) -> None:
        if self._writer is not None:
            self._writer.write(packet)
        # Keep raw accepted packets even when an earlier loss invalidated decode.
        if self.error is None:
            assert self._handler is not None
            self._handler(packet)
            self._manager.refresh()
            self._update_status()
        with self._state_lock:
            self._processed += 1

    def _run(self) -> None:
        try:
            if self._save_path is not None:
                if self._save_path.exists():
                    raise FileExistsError(f"refusing to overwrite existing capture: {self._save_path}")
                self._save_path.parent.mkdir(parents=True, exist_ok=True)
                self._writer = open_packet_writer(self._save_path)
            self._handler = make_packet_handler(self._manager)
            self._capture = LivePacketCapture(capture_options=self._options, on_packet=self._accept)
            self._capture.start()
            self._capture_started = True
            self._capture.raise_if_failed()
            self._ready.set()
            deadline = time.monotonic() + self._seconds if self._seconds is not None else None
            next_stats = 0.0
            while not self._stop_requested.is_set():
                self._capture.raise_if_failed()
                if not self._capture.running:
                    raise CaptureIntegrityError("Agris capture backend stopped unexpectedly")
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
                        self._manager.refresh(now)
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
                self._record_error(RuntimeError("Agris native cleanup is incomplete; retry stop()"))
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
        if self.error is None and self._detection_mode == "discovery":
            self._calibration_result = final_calibration_result(self.status, self.health)
        self._stopped.set()

    def stop(self) -> None:
        if not self._start_attempted:
            raise RuntimeError("Agris session was not started")
        if self._worker is current_thread():
            raise RuntimeError("Agris stop() cannot join its decoder thread")
        self._stop_requested.set()
        with self._lifecycle_lock:
            worker = self._worker
            if worker is not None and worker.is_alive():
                worker.join(self._JOIN_TIMEOUT)
            if worker is not None and worker.is_alive():
                with self._state_lock:
                    self._cleanup_incomplete = True
                self._record_error(RuntimeError("Agris decoder cleanup timed out; retry stop()"))
            elif self.cleanup_incomplete:
                self._shutdown()
            error = self.error
            if error is not None:
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(error, self, context="Agris stop")
                raise error

    def poll(self, timeout: float | None = None) -> AgrisBalance | None:
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (float, int))
                                    or not math.isfinite(timeout) or timeout < 0):
            raise ValueError("timeout must be finite and nonnegative")
        if not self._start_attempted:
            raise RuntimeError("Agris session was not started")
        if not self._consumer_lock.acquire(blocking=False):
            raise RuntimeError("Agris sessions support one balance consumer")
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

    def events(self) -> Iterator[AgrisBalance]:
        while True:
            balance = self.poll()
            if balance is not None:
                yield balance
            elif self.stopped:
                return

    def __enter__(self) -> LiveAgrisSession:
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
                _attach_cleanup_owner(exc_value, self, context="Agris context")
            exc_value.add_note(f"Agris context cleanup also failed: {cleanup!r}")
