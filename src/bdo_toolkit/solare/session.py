"""Controlled passive live capture for Arena of Solare snapshots."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread, current_thread
from types import TracebackType
from typing import Any, Optional

from bdo_toolkit._capture_backend import make_packet_handler
from bdo_toolkit._capture_options import PacketCaptureOptions
from bdo_toolkit._capture_runtime import (
    CaptureStats,
    LivePacketCapture,
    _attach_cleanup_owner,
)

from ._constants import (
    LIVE_CAPTURE_BUFFER_BYTES,
    LIVE_PACKET_QUEUE_MAX,
    LIVE_UPDATE_QUEUE_MAX,
    SOLARE_DEFAULT_CAPTURE_SECONDS,
)
from ._live_tracker import LiveSolareDiscoveryTracker
from ._replay_capture import SolareFrameCollector
from ._result import _resource_loss_summary, build_solare_result
from ._validation import validate_retain_raw_extensions
from .models import (
    SolareCaptureEndpoint,
    SolareCaptureHealth,
    SolareCaptureResult,
    SolareUpdate,
    SolareUpdateKind,
)


_POLL_INTERVAL_SECONDS = 0.2
_ACTIVE_UPDATE_SESSIONS: ContextVar[tuple[object, ...]] = ContextVar(
    "bdo_toolkit_active_solare_update_sessions",
    default=(),
)


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

    # Unknown Solare detail geometries are learned only after the complete
    # snapshot has been structurally confirmed.  That bounded, fail-closed
    # finalization can legitimately take several seconds on the full 720
    # records, so leave headroom beyond the historical five-second decoder
    # cleanup deadline while still bounding a genuinely stuck worker.
    _WORKER_STOP_TIMEOUT_SECONDS = 15.0

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
        if capture_options is not None and not isinstance(
            capture_options, PacketCaptureOptions
        ):
            raise TypeError("capture_options must be a PacketCaptureOptions or None")
        if not isinstance(stop_on_complete, bool):
            raise TypeError("stop_on_complete must be a boolean")
        retain_raw_extensions = validate_retain_raw_extensions(
            retain_raw_extensions
        )
        if on_update is not None and not callable(on_update):
            raise TypeError("on_update must be callable or None")

        self._capture_options = capture_options or PacketCaptureOptions()
        self._save_pcap = Path(save_pcap) if save_pcap is not None else None
        self._stop_on_complete = stop_on_complete
        self._retain_raw_extensions = retain_raw_extensions
        self._on_update = on_update
        self._capture_buffer_bytes = capture_buffer_bytes

        self._packet_queue: Queue[object] = Queue(maxsize=LIVE_PACKET_QUEUE_MAX)
        self._update_queue: Queue[SolareUpdate] = Queue(
            maxsize=LIVE_UPDATE_QUEUE_MAX
        )
        self._stop_requested = Event()
        self._stopped = Event()
        self._worker_ready = Event()
        self._state_lock = Lock()
        self._finish_lock = Lock()

        self._start_attempted = False
        self._started = False
        self._capture: Optional[LivePacketCapture] = None
        self._collector: Optional[SolareFrameCollector] = None
        self._tracker: Optional[LiveSolareDiscoveryTracker] = None
        self._worker: Optional[Thread] = None
        self._packet_handler: Optional[Callable[[object], None]] = None
        self._writer: Any = None
        self._saved_packets = 0
        self._traffic_announced = False
        self._tcp_gap_warning_announced = False
        self._confirmed_health: Optional[SolareCaptureHealth] = None
        self._result: Optional[SolareCaptureResult] = None
        self._error: Optional[BaseException] = None
        self._stop_reason: Optional[str] = None
        self._endpoint: Optional[SolareCaptureEndpoint] = None
        self._packet_queue_peak = 0
        self._packet_queue_overflows = 0
        self._decoder_failed = False
        self._cleanup_incomplete = False

    @property
    def running(self) -> bool:
        return self._started and not self._stopped.is_set()

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether capture cleanup remains owned and retryable."""

        return self._cleanup_incomplete

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

        return self._endpoint

    def start(self) -> None:
        """Open live capture and return once the adapter is ready."""

        # Final progress callbacks run while the worker owns ``_finish_lock``.
        # A same-session recursive start is always invalid, so reject the
        # already-attempted state before touching that lock instead of letting
        # callback misuse deadlock finalization.  The check inside the lock
        # remains authoritative for concurrent first-start attempts.
        if self._start_attempted:
            raise RuntimeError("live Solare session was already started")
        ready_update: Optional[SolareUpdate] = None
        with self._finish_lock:
            if self._start_attempted:
                raise RuntimeError("live Solare session was already started")
            self._start_attempted = True
            capture: Optional[LivePacketCapture] = None
            try:
                save_path = self._prepare_save_path()
                tracker = LiveSolareDiscoveryTracker(self._emit)
                collector = SolareFrameCollector(
                    self._capture_options.ports,
                    on_frame=tracker.observe,
                    on_traffic=self._announce_traffic,
                    retain_frames=False,
                )
                capture = LivePacketCapture(
                    capture_options=self._capture_options,
                    on_packet=self._enqueue_packet,
                    capture_buffer_bytes=self._capture_buffer_bytes,
                    require_capture_buffer=True,
                )

                self._tracker = tracker
                self._collector = collector
                self._capture = capture
                self._packet_handler = make_packet_handler(collector)

                capture.start()
                if save_path is not None:
                    self._writer = self._open_writer(save_path)

                endpoint = capture.endpoint
                if endpoint is not None:
                    self._endpoint = SolareCaptureEndpoint(
                        interface=endpoint.interface,
                        local_ip=endpoint.local_ip,
                        bpf_filter=endpoint.bpf_filter,
                    )
                endpoint_text = (
                    endpoint.interface if endpoint is not None else None
                ) or "Scapy default"
                endpoint_details = ""
                if endpoint is not None:
                    endpoint_details = (
                        f", local IP {endpoint.local_ip or 'any'}, "
                        f"filter {endpoint.bpf_filter or 'Python lfilter'}"
                    )
                recording = (
                    f", recording {save_path}" if save_path is not None else ""
                )

                worker = Thread(
                    target=self._run_worker_when_ready,
                    name="bdo-toolkit-solare",
                    daemon=True,
                )
                self._worker = worker
                worker.start()
                self._started = True
                ready_update = SolareUpdate(
                    kind=SolareUpdateKind.CAPTURE_READY,
                    message=(
                        f"passive Solare capture is ready on {endpoint_text}"
                        f"{endpoint_details}{recording}; "
                        "open the Leaderboard tab for its first load after "
                        "restarting the game"
                    ),
                )
                self._queue_update(ready_update)
            except BaseException as exc:
                self._worker_ready.set()
                self._record_error(exc)
                if self._writer is not None:
                    try:
                        self._writer.close()
                    except BaseException as cleanup_error:
                        self._record_error(cleanup_error)
                    self._writer = None
                if capture is not None and not capture.stopped:
                    try:
                        capture.stop()
                    except BaseException as cleanup_error:
                        self._record_error(cleanup_error)
                if capture is not None and not capture.stopped:
                    # The native callback still owns this session through
                    # _enqueue_packet(). Reject new packets, but retain every
                    # capture/decoder owner so stop() can retry cleanup.
                    self._cleanup_incomplete = True
                    self._started = True
                    self._stop_requested.set()
                    with self._state_lock:
                        self._stop_reason = "error"
                    _attach_cleanup_owner(
                        exc,
                        self,
                        context="live Solare startup",
                    )
                    raise
                while True:
                    try:
                        self._packet_queue.get_nowait()
                    except Empty:
                        break
                self._tracker = None
                self._collector = None
                self._capture = None
                self._packet_handler = None
                self._worker = None
                with self._state_lock:
                    self._stop_reason = "error"
                self._stopped.set()
                raise

        assert ready_update is not None
        try:
            self._notify_update(ready_update)
        finally:
            self._worker_ready.set()

    def _run_worker_when_ready(self) -> None:
        self._worker_ready.wait()
        self._run_worker()

    def stop(self) -> SolareCaptureResult:
        """Stop capture, drain every queued packet, and return the best result."""

        self._require_started()
        if not self._stopped.is_set():
            if self._inside_update_callback():
                raise RuntimeError(
                    "stop() cannot block inside on_update; use "
                    "request_stop() instead"
                )
            self.request_stop()
            self._worker_ready.set()
            worker = self._worker
            if (
                worker is not None
                and worker is not current_thread()
                and worker.is_alive()
            ):
                worker.join(timeout=self._WORKER_STOP_TIMEOUT_SECONDS)
                if worker.is_alive():
                    cleanup_error = RuntimeError(
                        "live Solare worker cleanup is incomplete after the "
                        f"{self._WORKER_STOP_TIMEOUT_SECONDS:g}-second deadline"
                    )
                    self._record_error(cleanup_error)
                    self._cleanup_incomplete = True
                    capture = self._capture
                    if capture is not None and not capture.stopped:
                        try:
                            capture.stop()
                        except BaseException as exc:
                            self._record_error(exc)
                    # The worker may still own tracker/collector callbacks.
                    # Never finalize or release those dependencies in parallel.
                    raise cleanup_error
            if not self._stopped.is_set():
                self._finish_worker(self.stop_reason or "requested")
        self.raise_if_failed()
        result = self.result
        if result is None:
            raise RuntimeError("live Solare session stopped without a result")
        return result

    def request_stop(self) -> None:
        """Request orderly shutdown without waiting for finalization.

        This is the callback-safe control method.  The terminal result remains
        available through :meth:`wait`, :meth:`stop`, or the ``finished``
        update after the callback returns.
        """

        self._require_started()
        if self._stopped.is_set() or self.result is not None:
            return
        self._set_requested_reason("requested")
        self._stop_requested.set()

    def wait(self, timeout: Optional[float] = None) -> Optional[SolareCaptureResult]:
        """Wait for automatic/manual completion, returning ``None`` on timeout."""

        self._require_started()
        _validate_timeout(timeout, name="timeout")
        if self._inside_update_callback() and not self._stopped.is_set():
            result = self.result
            if result is not None:
                self.raise_if_failed()
                return result
            raise RuntimeError(
                "wait() cannot block inside on_update; use request_stop() "
                "and wait after the callback returns"
            )
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._stopped.is_set():
            if self._cleanup_incomplete:
                self.raise_if_failed()
            if deadline is None:
                wait_seconds = _POLL_INTERVAL_SECONDS
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                wait_seconds = min(_POLL_INTERVAL_SECONDS, remaining)
            if self._stopped.wait(timeout=wait_seconds):
                break
        self.raise_if_failed()
        return self.result

    def poll(self, timeout: Optional[float] = None) -> Optional[SolareUpdate]:
        """Return one progress update, or ``None`` on timeout/end-of-stream."""

        self._require_started()
        _validate_timeout(timeout, name="timeout")
        if self._inside_update_callback():
            raise RuntimeError(
                "poll() cannot consume updates inside on_update; consume "
                "them outside the callback"
            )
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                return self._update_queue.get_nowait()
            except Empty:
                pass
            if self._stopped.is_set():
                self.raise_if_failed()
                return None
            if self._cleanup_incomplete:
                self.raise_if_failed()
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
                    self._service_drained_clocks()
                    tracker = self._tracker
                    if (
                        self._stop_on_complete
                        and tracker is not None
                        and tracker.complete
                    ):
                        reason = "complete-snapshot"
                        break
                    continue

                self._process_packet(packet)
                self._service_drained_clocks()
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
            self._stop_requested.set()
            capture = self._capture
            collector = self._collector
            tracker = self._tracker
            stats = None
            result: Optional[SolareCaptureResult] = None
            stop_failure: Optional[BaseException] = None
            if capture is not None:
                try:
                    stats = capture.stop()
                except BaseException as exc:
                    stop_failure = exc
                    self._record_error(exc)
                try:
                    if capture.error is not None:
                        self._record_error(capture.error)
                except BaseException as exc:
                    self._record_error(exc)
                if not capture.stopped:
                    cleanup_error = (
                        getattr(capture, "cleanup_error", None)
                        or stop_failure
                        or RuntimeError(
                            "live Solare capture cleanup is incomplete"
                        )
                    )
                    self._record_error(cleanup_error)
                    self._cleanup_incomplete = True
                    return
            try:
                while True:
                    try:
                        packet = self._packet_queue.get_nowait()
                    except Empty:
                        break
                    if self._decoder_failed:
                        self._write_packet(packet)
                        continue
                    try:
                        self._process_packet(packet)
                    except BaseException as exc:
                        self._record_error(exc)
                        self._decoder_failed = True

                if collector is None or tracker is None:
                    self._record_error(
                        RuntimeError("live Solare decoder was not initialized")
                    )
                    self._decoder_failed = True
                else:
                    try:
                        collector.finish()
                    except BaseException as exc:
                        self._record_error(exc)
                        self._decoder_failed = True
                    if not self._decoder_failed:
                        try:
                            tracker.refresh()
                        except BaseException as exc:
                            self._record_error(exc)
                            self._decoder_failed = True

                self._close_writer()

                health: Optional[SolareCaptureHealth] = None
                if collector is not None:
                    try:
                        health = self._collector_health(collector, stats)
                    except BaseException as exc:
                        self._record_error(exc)

                if (
                    collector is not None
                    and tracker is not None
                    and health is not None
                    and not self._decoder_failed
                ):
                    try:
                        confirmed_frames = getattr(
                            tracker,
                            "confirmed_frames",
                            None,
                        )
                        retained_frames = getattr(
                            tracker,
                            "retained_frames",
                            (),
                        )
                        result_frames = (
                            confirmed_frames
                            or retained_frames
                            or collector.frames
                        )
                        discovery = getattr(tracker, "result", None)
                        if discovery is None:
                            result = build_solare_result(
                                result_frames,
                                self._confirmed_health or health,
                                retain_raw_extensions=self._retain_raw_extensions,
                            )
                        else:
                            result = build_solare_result(
                                result_frames,
                                self._confirmed_health or health,
                                retain_raw_extensions=self._retain_raw_extensions,
                                _discovery=discovery,
                            )
                        resource_loss = _resource_loss_summary(health)
                        if (
                            result.complete
                            and self._confirmed_health is not None
                            and self._confirmed_health.capture_is_clean
                            and resource_loss is not None
                        ):
                            base_message = result.message or (
                                "structurally confirmed Solare leaderboard"
                            )
                            if (
                                reason == "resource-limit"
                                or self.stop_reason == "resource-limit"
                            ):
                                continuation = (
                                    "the already-confirmed snapshot remains "
                                    "valid, but continued capture ended due to "
                                    f"resource pressure: {resource_loss}"
                                )
                            else:
                                continuation = (
                                    "the already-confirmed snapshot remains "
                                    "valid, but continued capture later lost "
                                    f"integrity because {resource_loss}"
                                )
                            result = replace(
                                result,
                                message=f"{base_message}; {continuation}",
                            )
                    except BaseException as exc:
                        self._record_error(exc)

                with self._state_lock:
                    self._result = result

                if result is not None:
                    resource_loss = (
                        _resource_loss_summary(health)
                        if health is not None
                        else None
                    )
                    if resource_loss is not None:
                        self._emit(
                            SolareUpdate(
                                kind=SolareUpdateKind.WARNING,
                                message=(
                                    "live capture integrity was lost because "
                                    f"{resource_loss}; retry after reducing "
                                    "capture load"
                                ),
                                ranked_players=result.evidence.ranked_players,
                                overall_players=result.evidence.overall_players,
                                exact_cross_check=(
                                    result.evidence.exact_cross_check
                                ),
                            )
                        )
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
            except BaseException as exc:
                self._record_error(exc)
            finally:
                self._close_writer()
                with self._state_lock:
                    if self._error is not None:
                        self._stop_reason = "error"
                    elif self._stop_reason is None:
                        self._stop_reason = reason
                self._collector = None
                self._tracker = None
                self._packet_handler = None
                self._capture = None
                self._confirmed_health = None
                self._worker = None
                self._cleanup_incomplete = False
                self._stopped.set()

    def _process_packet(self, packet: object) -> None:
        # Record the exact packet accepted by the capture callback before any
        # semantic work can fail.  This makes an opt-in PCAP useful for patch
        # drift and decoder failures, while all writing still stays off the
        # native capture thread.
        self._write_packet(packet)
        handler = self._packet_handler
        if handler is None:
            raise RuntimeError("live Solare packet handler was not initialized")
        try:
            handler(packet)
        except BaseException:
            self._decoder_failed = True
            raise
        self._announce_tcp_gap_loss()

        tracker = self._tracker
        if tracker is not None and tracker.complete:
            self._latch_confirmation()

    def _service_drained_clocks(self) -> None:
        """Advance live-only clocks only after queued packet work is caught up.

        Wall-clock TCP-gap recovery or candidate-tail closure while packets
        remain queued could skip a delayed prefix or a later same-family
        frame that Npcap already delivered. Waiting for an empty decode queue
        preserves that evidence. The second check protects candidate
        finalization from packets enqueued while gap service was running.
        """

        if not self._packet_queue.empty():
            return

        collector = self._collector
        if collector is not None:
            collector.service_gaps(time.time())
            self._announce_tcp_gap_loss()

        if not self._packet_queue.empty():
            return

        tracker = self._tracker
        if tracker is not None:
            tracker.service_candidate_idle(time.monotonic())
            self._latch_confirmation()

    def _write_packet(self, packet: object) -> None:
        if self._writer is not None:
            try:
                self._writer.write(packet)
                self._saved_packets += 1
                if self._saved_packets % 128 == 0:
                    self._writer.flush()
            except BaseException as exc:
                self._record_error(exc)
                self._set_requested_reason("error")
                self._stop_requested.set()
                self._close_writer()

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
        tracker = self._tracker
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
            retained_large_messages=getattr(
                tracker,
                "observed_frame_count",
                len(collector.frames),
            ),
            candidate_messages_observed=getattr(
                tracker,
                "observed_frame_count",
                0,
            ),
            candidate_frames_retained=getattr(
                tracker,
                "retained_frame_count",
                0,
            ),
            candidate_bytes_retained=getattr(
                tracker,
                "retained_bytes",
                0,
            ),
            peak_candidate_frames=getattr(
                tracker,
                "peak_retained_frame_count",
                0,
            ),
            peak_candidate_bytes=getattr(
                tracker,
                "peak_retained_bytes",
                0,
            ),
            candidate_frames_evicted=getattr(
                tracker,
                "evicted_frame_count",
                0,
            ),
            candidate_bytes_evicted=getattr(
                tracker,
                "evicted_bytes",
                0,
            ),
            candidate_history_rolled_over=getattr(
                tracker,
                "history_rolled_over",
                False,
            ),
            packet_queue_peak=self._packet_queue_peak,
            packet_queue_overflows=self._packet_queue_overflows,
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

    def _announce_tcp_gap_loss(self) -> None:
        """Warn once when this pre-confirmation attempt becomes ineligible."""

        collector = self._collector
        if (
            self._tcp_gap_warning_announced
            or self._confirmed_health is not None
            or collector is None
            or collector.tcp_gap_resets == 0
        ):
            return
        self._tcp_gap_warning_announced = True
        count = collector.tcp_gap_resets
        self._emit(
            SolareUpdate(
                kind=SolareUpdateKind.WARNING,
                message=(
                    "TCP reassembly reset "
                    f"{count} time{'s' if count != 1 else ''} after an "
                    "unresolved sequence gap; this capture attempt will "
                    "remain fail-closed. Stop and retry with a fresh capture"
                ),
            )
        )

    def _enqueue_packet(self, packet: object) -> None:
        if self._stop_requested.is_set():
            return
        try:
            self._packet_queue.put_nowait(packet)
        except Full:
            with self._state_lock:
                self._packet_queue_overflows += 1
                if self._stop_reason is None:
                    self._stop_reason = "resource-limit"
            self._stop_requested.set()
            return
        depth = self._packet_queue.qsize()
        with self._state_lock:
            self._packet_queue_peak = max(self._packet_queue_peak, depth)

    def _emit(self, update: SolareUpdate) -> None:
        # Structural confirmation is atomic before user code observes it.
        # A slow callback may allow later packets or resource loss to arrive,
        # but those events cannot retroactively invalidate the proven window.
        if update.kind is SolareUpdateKind.SNAPSHOT_CONFIRMED:
            self._latch_confirmation()
        self._queue_update(update)
        self._notify_update(update)

    def _queue_update(self, update: SolareUpdate) -> None:
        while True:
            try:
                self._update_queue.put_nowait(update)
                break
            except Full:
                try:
                    self._update_queue.get_nowait()
                except Empty:
                    continue

    def _notify_update(self, update: SolareUpdate) -> None:
        if self._on_update is not None:
            active_sessions = _ACTIVE_UPDATE_SESSIONS.get()
            token = _ACTIVE_UPDATE_SESSIONS.set(active_sessions + (self,))
            try:
                self._on_update(update)
            except BaseException as exc:
                self._record_error(exc)
                self._set_requested_reason("error")
                self._stop_requested.set()
            finally:
                _ACTIVE_UPDATE_SESSIONS.reset(token)

    def _inside_update_callback(self) -> bool:
        return self in _ACTIVE_UPDATE_SESSIONS.get()

    def _close_writer(self) -> None:
        writer = self._writer
        if writer is None:
            return
        self._writer = None
        try:
            writer.close()
        except BaseException as exc:
            self._record_error(exc)

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
        if not self._started:
            return
        if exc_value is None:
            self.stop()
            return
        try:
            self.stop()
        except BaseException as cleanup_error:
            # The exception already leaving the user's block remains primary;
            # the first session failure is still available through ``error``.
            if self.cleanup_incomplete:
                _attach_cleanup_owner(
                    exc_value,
                    self,
                    context="live Solare context",
                )
            exc_value.add_note(
                "live Solare context cleanup also failed: "
                f"{cleanup_error!r}"
            )


def capture_solare_snapshot(
    *,
    capture_options: Optional[PacketCaptureOptions] = None,
    capture_seconds: Optional[float] = SOLARE_DEFAULT_CAPTURE_SECONDS,
    save_pcap: str | Path | None = None,
    stop_on_complete: bool = True,
    retain_raw_extensions: bool = False,
    on_update: Optional[Callable[[SolareUpdate], None]] = None,
    capture_buffer_bytes: int = LIVE_CAPTURE_BUFFER_BYTES,
) -> SolareCaptureResult:
    """Blocking convenience wrapper around :class:`LiveSolareSession`."""

    _validate_timeout(capture_seconds, name="capture_seconds")
    session = LiveSolareSession(
        capture_options=capture_options,
        save_pcap=save_pcap,
        stop_on_complete=stop_on_complete,
        retain_raw_extensions=retain_raw_extensions,
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
        try:
            return session.stop()
        except BaseException as exc:
            if session.cleanup_incomplete:
                _attach_cleanup_owner(
                    exc,
                    session,
                    context="live Solare convenience wrapper",
                )
            raise
    except BaseException as exc:
        if session.running:
            try:
                session.stop()
            except BaseException as cleanup_error:
                if session.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc,
                        session,
                        context="live Solare convenience wrapper",
                    )
                if cleanup_error is not exc:
                    exc.add_note(
                        "live Solare convenience cleanup also failed: "
                        f"{cleanup_error!r}"
                    )
        raise
