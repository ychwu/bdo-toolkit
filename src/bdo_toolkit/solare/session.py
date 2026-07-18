"""Controlled passive live capture for Arena of Solare snapshots."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Lock, Thread, current_thread
from types import TracebackType
from typing import Any, Optional

from bdo_toolkit._capture_backend import make_packet_handler
from bdo_toolkit._capture_options import PacketCaptureOptions
from bdo_toolkit._capture_runtime import CaptureStats, LivePacketCapture

from ._constants import LIVE_CAPTURE_BUFFER_BYTES
from ._live_tracker import LiveSolareDiscoveryTracker
from ._replay_capture import SolareFrameCollector
from ._result import build_solare_result
from .models import (
    SolareCaptureEndpoint,
    SolareCaptureHealth,
    SolareCaptureResult,
    SolareUpdate,
    SolareUpdateKind,
)


_POLL_INTERVAL_SECONDS = 0.2


def _validate_timeout(value: Optional[float], *, name: str) -> None:
    if value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{name} must be finite and non-negative")


class LiveSolareSession:
    """Single-use live session that assembles one structural snapshot.

    Packet acquisition runs in Scapy's thread, while pcap writing, TCP
    reassembly, discovery, and detailed decoding run in a separate worker.
    This keeps the capture callback small enough for the multi-megabyte
    leaderboard burst. Structural discovery receives no known Solare opcode or
    saved layout; validated detail fingerprints are considered only after the
    ranking tables independently confirm.
    """

    def __init__(
        self,
        *,
        capture_options: Optional[PacketCaptureOptions] = None,
        save_pcap: str | Path | None = None,
        stop_on_complete: bool = True,
        on_update: Optional[Callable[[SolareUpdate], None]] = None,
        capture_buffer_bytes: int = LIVE_CAPTURE_BUFFER_BYTES,
    ) -> None:
        if capture_options is not None and not isinstance(
            capture_options, PacketCaptureOptions
        ):
            raise TypeError("capture_options must be a PacketCaptureOptions or None")
        if not isinstance(stop_on_complete, bool):
            raise TypeError("stop_on_complete must be a boolean")
        if on_update is not None and not callable(on_update):
            raise TypeError("on_update must be callable or None")

        self._capture_options = capture_options or PacketCaptureOptions()
        self._save_pcap = Path(save_pcap) if save_pcap is not None else None
        self._stop_on_complete = stop_on_complete
        self._on_update = on_update
        self._capture_buffer_bytes = capture_buffer_bytes

        self._packet_queue: Queue[object] = Queue()
        self._update_queue: Queue[SolareUpdate] = Queue()
        self._stop_requested = Event()
        self._stopped = Event()
        self._state_lock = Lock()
        self._finish_lock = Lock()

        self._started = False
        self._capture: Optional[LivePacketCapture] = None
        self._collector: Optional[SolareFrameCollector] = None
        self._tracker: Optional[LiveSolareDiscoveryTracker] = None
        self._worker: Optional[Thread] = None
        self._packet_handler: Optional[Callable[[object], None]] = None
        self._writer: Any = None
        self._saved_packets = 0
        self._traffic_announced = False
        self._confirmed_health: Optional[SolareCaptureHealth] = None
        self._result: Optional[SolareCaptureResult] = None
        self._error: Optional[BaseException] = None
        self._stop_reason: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._started and not self._stopped.is_set()

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    @property
    def result(self) -> Optional[SolareCaptureResult]:
        """The final result after manual or automatic shutdown."""

        with self._state_lock:
            return self._result

    @property
    def error(self) -> Optional[BaseException]:
        with self._state_lock:
            return self._error

    @property
    def stop_reason(self) -> Optional[str]:
        with self._state_lock:
            return self._stop_reason

    @property
    def endpoint(self) -> Optional[SolareCaptureEndpoint]:
        """Resolved live-capture target, exposed as a Solare public model."""

        capture = self._capture
        endpoint = capture.endpoint if capture is not None else None
        if endpoint is None:
            return None
        return SolareCaptureEndpoint(
            interface=endpoint.interface,
            local_ip=endpoint.local_ip,
            bpf_filter=endpoint.bpf_filter,
        )

    def start(self) -> None:
        """Open live capture and return once the adapter is ready."""

        with self._finish_lock:
            if self._started:
                raise RuntimeError("live Solare session was already started")
            save_path = self._prepare_save_path()
            tracker = LiveSolareDiscoveryTracker(self._emit)
            collector = SolareFrameCollector(
                self._capture_options.ports,
                on_frame=tracker.observe,
                on_traffic=self._announce_traffic,
            )
            capture = LivePacketCapture(
                capture_options=self._capture_options,
                on_packet=self._packet_queue.put_nowait,
                capture_buffer_bytes=self._capture_buffer_bytes,
                require_capture_buffer=True,
            )

            self._tracker = tracker
            self._collector = collector
            self._capture = capture
            self._packet_handler = make_packet_handler(collector)

            capture_started = False
            try:
                capture.start()
                capture_started = True
                if save_path is not None:
                    self._writer = self._open_writer(save_path)
            except BaseException:
                if (capture_started or capture.running) and not capture.stopped:
                    try:
                        capture.stop()
                    except BaseException:
                        pass
                self._tracker = None
                self._collector = None
                self._capture = None
                self._packet_handler = None
                raise

            self._started = True
            endpoint = capture.endpoint
            endpoint_text = (
                endpoint.interface if endpoint is not None else None
            ) or "Scapy default"
            endpoint_details = ""
            if endpoint is not None:
                endpoint_details = (
                    f", local IP {endpoint.local_ip or 'any'}, "
                    f"filter {endpoint.bpf_filter or 'Python lfilter'}"
                )
            recording = f", recording {save_path}" if save_path is not None else ""
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.CAPTURE_READY,
                    message=(
                        f"passive Solare capture is ready on {endpoint_text}"
                        f"{endpoint_details}{recording}; "
                        "open or refresh the Leaderboard tab"
                    ),
                )
            )
            worker = Thread(
                target=self._run_worker,
                name="bdo-toolkit-solare",
                daemon=True,
            )
            self._worker = worker
            worker.start()

    def stop(self) -> SolareCaptureResult:
        """Stop capture, drain every queued packet, and return the best result."""

        self._require_started()
        if not self._stopped.is_set():
            self._set_requested_reason("requested")
            self._stop_requested.set()
            worker = self._worker
            if worker is not None and worker is not current_thread():
                worker.join()
        self.raise_if_failed()
        result = self.result
        if result is None:
            raise RuntimeError("live Solare session stopped without a result")
        return result

    def wait(self, timeout: Optional[float] = None) -> Optional[SolareCaptureResult]:
        """Wait for automatic/manual completion, returning ``None`` on timeout."""

        self._require_started()
        _validate_timeout(timeout, name="timeout")
        if not self._stopped.wait(timeout=timeout):
            return None
        self.raise_if_failed()
        return self.result

    def poll(self, timeout: Optional[float] = None) -> Optional[SolareUpdate]:
        """Return one progress update, or ``None`` on timeout/end-of-stream."""

        self._require_started()
        _validate_timeout(timeout, name="timeout")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                return self._update_queue.get_nowait()
            except Empty:
                pass
            if self._stopped.is_set():
                self.raise_if_failed()
                return None
            if deadline is None:
                wait_seconds = _POLL_INTERVAL_SECONDS
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                wait_seconds = min(_POLL_INTERVAL_SECONDS, remaining)
            try:
                return self._update_queue.get(timeout=wait_seconds)
            except Empty:
                continue

    def updates(self) -> Iterator[SolareUpdate]:
        """Yield structured progress until the final update is drained."""

        while True:
            update = self.poll()
            if update is None:
                return
            yield update

    def raise_if_failed(self) -> None:
        error = self.error
        if error is not None:
            raise error

    def _run_worker(self) -> None:
        reason = "capture-ended"
        try:
            while not self._stop_requested.is_set():
                capture = self._capture
                if capture is None:
                    raise RuntimeError("live capture owner disappeared")
                capture_error = capture.error
                if capture_error is not None:
                    raise capture_error

                try:
                    packet = self._packet_queue.get(timeout=_POLL_INTERVAL_SECONDS)
                except Empty:
                    if not capture.running:
                        reason = "capture-ended"
                        break
                    tracker = self._tracker
                    if tracker is not None:
                        # Progress milestones intentionally avoid rescanning on
                        # every frame. An idle queue marks the end of a burst,
                        # so refresh once for exact-size retry windows whose
                        # final count falls between those milestones.
                        tracker.refresh()
                        self._latch_confirmation()
                        if self._stop_on_complete and tracker.complete:
                            reason = "complete-snapshot"
                            break
                    continue

                self._process_packet(packet)
                tracker = self._tracker
                if (
                    self._stop_on_complete
                    and tracker is not None
                    and tracker.complete
                ):
                    reason = "complete-snapshot"
                    break

            requested_reason = self.stop_reason
            if requested_reason is not None:
                reason = requested_reason
        except BaseException as exc:
            self._record_error(exc)
            reason = "error"
        finally:
            self._finish_worker(reason)

    def _finish_worker(self, reason: str) -> None:
        with self._finish_lock:
            if self._stopped.is_set():
                return
            capture = self._capture
            collector = self._collector
            tracker = self._tracker
            stats = None
            try:
                if capture is not None:
                    stats = capture.stop()
                    if capture.error is not None:
                        self._record_error(capture.error)

                while True:
                    try:
                        packet = self._packet_queue.get_nowait()
                    except Empty:
                        break
                    self._process_packet(packet)

                if collector is None or tracker is None:
                    raise RuntimeError("live Solare decoder was not initialized")
                collector.finish()
                tracker.refresh()
            except BaseException as exc:
                self._record_error(exc)
            finally:
                if self._writer is not None:
                    try:
                        self._writer.close()
                    except BaseException as exc:
                        self._record_error(exc)
                    self._writer = None

            result = None
            if collector is not None:
                health = self._collector_health(collector, stats)
                try:
                    confirmed_frames = (
                        getattr(tracker, "confirmed_frames", None)
                        if tracker is not None
                        else None
                    )
                    result = build_solare_result(
                        confirmed_frames or collector.frames,
                        self._confirmed_health or health,
                    )
                except BaseException as exc:
                    self._record_error(exc)

            with self._state_lock:
                self._result = result
                self._stop_reason = "error" if self._error is not None else reason

            if result is not None:
                self._emit(
                    SolareUpdate(
                        kind=SolareUpdateKind.FINISHED,
                        message=(
                            f"Solare capture finished with status "
                            f"{result.status.value}"
                        ),
                        ranked_players=result.evidence.ranked_players,
                        overall_players=result.evidence.overall_players,
                        exact_cross_check=result.evidence.exact_cross_check,
                        result=result,
                    )
                )
            if self.error is not None:
                with self._state_lock:
                    self._stop_reason = "error"
            self._stopped.set()

    def _process_packet(self, packet: object) -> None:
        handler = self._packet_handler
        if handler is None:
            raise RuntimeError("live Solare packet handler was not initialized")
        handler(packet)
        if self._writer is not None:
            self._writer.write(packet)
            self._saved_packets += 1
            if self._saved_packets % 128 == 0:
                self._writer.flush()
        tracker = self._tracker
        if tracker is not None and tracker.complete:
            self._latch_confirmation()

    def _latch_confirmation(self) -> None:
        tracker = self._tracker
        collector = self._collector
        if tracker is None or not tracker.complete or collector is None:
            return
        if self._confirmed_health is None:
            capture = self._capture
            stats = capture.snapshot_stats() if capture is not None else None
            self._confirmed_health = self._collector_health(collector, stats)
        collector.stop_retaining()

    def _collector_health(
        self,
        collector: SolareFrameCollector,
        stats: Optional[CaptureStats],
    ) -> SolareCaptureHealth:
        return collector.health(
            saved_packets=self._saved_packets,
            pcap_received=stats.received if stats is not None else None,
            pcap_dropped=stats.dropped if stats is not None else None,
            pcap_interface_dropped=(
                stats.interface_dropped if stats is not None else None
            ),
            capture_buffer_bytes=(
                stats.capture_buffer_bytes if stats is not None else None
            ),
        )

    def _announce_traffic(self) -> None:
        if self._traffic_announced:
            return
        self._traffic_announced = True
        self._emit(
            SolareUpdate(
                kind=SolareUpdateKind.TRAFFIC,
                message="inbound game-server traffic is flowing",
            )
        )

    def _emit(self, update: SolareUpdate) -> None:
        self._update_queue.put_nowait(update)
        if self._on_update is not None:
            try:
                self._on_update(update)
            except BaseException as exc:
                self._record_error(exc)
                self._set_requested_reason("error")
                self._stop_requested.set()

    def _record_error(self, error: BaseException) -> None:
        with self._state_lock:
            if self._error is None:
                self._error = error

    def _set_requested_reason(self, reason: str) -> None:
        with self._state_lock:
            if self._stop_reason is None:
                self._stop_reason = reason

    def _prepare_save_path(self) -> Optional[Path]:
        if self._save_pcap is None:
            return None
        path = self._save_pcap.expanduser().resolve()
        if path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError("save_pcap must end in .pcap or .pcapng")
        if path.exists():
            raise FileExistsError(f"refusing to overwrite existing capture: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _open_writer(path: Path) -> Any:
        from scapy.utils import PcapNgWriter, PcapWriter  # type: ignore

        if path.suffix.lower() == ".pcapng":
            return PcapNgWriter(str(path))
        return PcapWriter(str(path), sync=True)

    def _require_started(self) -> None:
        if not self._started:
            raise RuntimeError("live Solare session was not started")

    def __enter__(self) -> "LiveSolareSession":
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._started and not self._stopped.is_set():
            self.stop()


def capture_solare_snapshot(
    *,
    capture_options: Optional[PacketCaptureOptions] = None,
    capture_seconds: Optional[float] = None,
    save_pcap: str | Path | None = None,
    stop_on_complete: bool = True,
    on_update: Optional[Callable[[SolareUpdate], None]] = None,
    capture_buffer_bytes: int = LIVE_CAPTURE_BUFFER_BYTES,
) -> SolareCaptureResult:
    """Blocking convenience wrapper around :class:`LiveSolareSession`."""

    _validate_timeout(capture_seconds, name="capture_seconds")
    session = LiveSolareSession(
        capture_options=capture_options,
        save_pcap=save_pcap,
        stop_on_complete=stop_on_complete,
        on_update=on_update,
        capture_buffer_bytes=capture_buffer_bytes,
    )
    session.start()
    started_at = time.monotonic()
    try:
        while True:
            timeout = _POLL_INTERVAL_SECONDS
            if capture_seconds is not None:
                remaining = capture_seconds - (time.monotonic() - started_at)
                if remaining <= 0:
                    return session.stop()
                timeout = min(timeout, remaining)
            result = session.wait(timeout=timeout)
            if result is not None:
                return result
    except KeyboardInterrupt:
        return session.stop()
    finally:
        if session.running:
            session.stop()
