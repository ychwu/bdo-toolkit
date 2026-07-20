"""Packet capture and pcap replay APIs."""

from __future__ import annotations

from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass
import math
import time
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, RLock, Thread, Timer, current_thread
from typing import Callable, Iterator, Optional

from ._capture_backend import (
    iter_pcap_file,
    make_packet_handler,
    validate_server_ports,
)
from ._capture_options import LiveCaptureOptions
from ._capture_runtime import (
    CaptureEndpoint,
    CaptureStats,
    LivePacketCapture,
    _attach_cleanup_owner,
)
from ._deposit_origin import DecrementSpec, DepositOriginTracker
from ._engine import PacketEngine, toolkit_event_from_record
from ._protocol import (
    DEFAULT_SERVER_PORTS,
    LootEvent,
)
from ._specs import _parse_opcode, event_specs_from_profile
from .events import BDOEvent
from .filters import EventFilter
from .origin_learning import CompanionObservation
from .profiles import (
    OpcodeProfile,
    OriginCompanionFamily,
    ProfileError,
    default_profile_path,
    load_opcode_profile,
)


_PACKET_WORKER_STOP = object()
_ACTIVE_ORIGIN_SESSIONS: ContextVar[tuple[object, ...]] = ContextVar(
    "bdo_toolkit_active_origin_session",
    default=(),
)


class CaptureIntegrityError(RuntimeError):
    """Live acquisition lost data before the decoder could inspect it."""


@dataclass(frozen=True)
class LiveCaptureHealth:
    """Bounded-queue, TCP-reassembly, and native-capture diagnostics.

    A non-clean result means the event stream may be incomplete.  Queue
    overflow is fail-closed: the session records :class:`CaptureIntegrityError`
    and requests shutdown instead of silently continuing with missing packets.
    """

    packets_accepted: int = 0
    packet_queue_peak: int = 0
    packet_queue_overflows: int = 0
    event_queue_peak: int = 0
    tcp_gap_resets: int = 0
    flow_state_evictions: int = 0
    pcap_received: Optional[int] = None
    pcap_dropped: Optional[int] = None
    pcap_interface_dropped: Optional[int] = None
    capture_buffer_bytes: Optional[int] = None
    capture_buffer_fallback: bool = False

    @property
    def capture_is_clean(self) -> bool:
        """Whether known acquisition-loss indicators remained clear."""

        return (
            self.packet_queue_overflows == 0
            and self.tcp_gap_resets == 0
            and self.flow_state_evictions == 0
            and self.pcap_dropped in (None, 0)
            and self.pcap_interface_dropped in (None, 0)
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready diagnostic mapping."""

        result: dict[str, object] = {
            "packets_accepted": self.packets_accepted,
            "packet_queue_peak": self.packet_queue_peak,
            "packet_queue_overflows": self.packet_queue_overflows,
            "event_queue_peak": self.event_queue_peak,
            "tcp_gap_resets": self.tcp_gap_resets,
            "flow_state_evictions": self.flow_state_evictions,
            "capture_buffer_fallback": self.capture_buffer_fallback,
            "capture_is_clean": self.capture_is_clean,
        }
        optional = {
            "pcap_received": self.pcap_received,
            "pcap_dropped": self.pcap_dropped,
            "pcap_interface_dropped": self.pcap_interface_dropped,
            "capture_buffer_bytes": self.capture_buffer_bytes,
        }
        result.update(
            {key: value for key, value in optional.items() if value is not None}
        )
        return result


def _load_selected_profile(path: Path) -> OpcodeProfile:
    if not path.is_file():
        raise FileNotFoundError(f"Opcode profile does not exist: {path}")
    profile = load_opcode_profile(path)
    if not profile.active:
        raise ProfileError(
            f"Opcode profile is inactive: {path}. Activate or recalibrate it "
            "instead of silently falling back to another opcode authority."
        )
    return profile


def _decrement_specs(
    profile: OpcodeProfile,
) -> tuple[DecrementSpec, ...]:
    """Position-exact source-stack-decrement shapes from the active profile.

    Missing optional geometry deliberately remains a lower-confidence
    quantity-only shape. Malformed declared geometry is different: skip that
    entry instead of silently degrading it to the collision-prone heuristic.
    """
    specs: list[DecrementSpec] = []
    for entry in profile.specs.get("SOURCE_STACK_DECREMENT", []):
        opcode = _parse_opcode(entry.get("opcode"))
        length = entry.get("length")
        offset = entry.get("quantity_removed_offset")
        source_instance_offset = entry.get("source_instance_offset")
        repeat_stride = entry.get("repeat_stride")
        if (
            opcode is not None
            and isinstance(length, int)
            and not isinstance(length, bool)
            and length >= 5
            and isinstance(offset, int)
            and not isinstance(offset, bool)
            and offset >= 0
            and offset + 4 <= length
        ):
            if source_instance_offset is not None and not (
                isinstance(source_instance_offset, int)
                and not isinstance(source_instance_offset, bool)
                and source_instance_offset >= 0
                and source_instance_offset + 8 <= length
            ):
                continue
            if repeat_stride is not None and not (
                isinstance(repeat_stride, int)
                and not isinstance(repeat_stride, bool)
                and repeat_stride > 0
            ):
                continue
            if repeat_stride is not None:
                prefix_length = length - repeat_stride
                if (
                    prefix_length < 5
                    or offset < prefix_length
                    or (
                        source_instance_offset is not None
                        and source_instance_offset < prefix_length
                    )
                ):
                    continue
            specs.append(
                DecrementSpec(
                    opcode,
                    length,
                    offset,
                    source_instance_offset=source_instance_offset,
                    repeat_stride=repeat_stride,
                )
            )
    return tuple(specs)


def _origin_companion_families(
    profile: OpcodeProfile,
) -> tuple[OriginCompanionFamily, ...]:
    return profile.origin_companion_families


def _needs_origin_tracking(
    event_filter: Optional[EventFilter],
    origin_observer: Optional[Callable[[CompanionObservation], object]],
) -> bool:
    if origin_observer is not None or event_filter is None:
        return True
    return event_filter.event_types is None or bool(
        event_filter.event_types & {"storage_delta", "storage_record"}
    )


class _EventCollector:
    """Wire a PacketEngine to app-facing events with optional filtering.

    Live storage deltas and neutral storage records take a short detour through
    the deposit-origin tracker (a few frames of lookahead). Independent manual
    or worker evidence can promote an unfamiliar-mode ``storage_record`` to a
    confirmed-live ``storage_delta``; records without that evidence remain
    neutral. All other events emit immediately, which can place a deferred
    storage event slightly after later events of other types. Timestamps are
    unaffected.
    """

    def __init__(
        self,
        *,
        server_ports: tuple[int, ...],
        event_filter: Optional[EventFilter] = None,
        on_event: Optional[Callable[[BDOEvent], None]] = None,
        opcode_profile: str | Path | None = None,
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
    ) -> None:
        profile_path = (
            Path(opcode_profile)
            if opcode_profile is not None
            else default_profile_path()
        )
        profile = _load_selected_profile(profile_path)
        loaded_specs = event_specs_from_profile(profile)
        self._events: deque[BDOEvent] = deque()
        self.event_filter = event_filter
        self.on_event = on_event
        self.profile_source = f"{loaded_specs.source} active profile"
        self._tracker: Optional[DepositOriginTracker] = None
        if _needs_origin_tracking(event_filter, origin_observer):
            self._tracker = DepositOriginTracker(
                decrement_specs=_decrement_specs(profile),
                emit=self._deliver,
                origin_observer=origin_observer,
                known_companion_families=_origin_companion_families(profile),
                storage_delta_opcodes=(
                    spec.opcode
                    for spec in loaded_specs.specs
                    if spec.label == "INVENTORY_TO_STORAGE"
                ),
            )
        tracker = self._tracker
        self.engine = PacketEngine(
            server_ports=server_ports,
            event_specs=loaded_specs.specs,
            on_event=self._handle_record,
            frame_observer=(tracker.observe_frame if tracker is not None else None),
            stream_observer=(tracker.observe_stream if tracker is not None else None),
            flow_close_observer=(tracker.close_flow if tracker is not None else None),
        )

    def _handle_record(self, record: LootEvent, raw_message: bytes) -> None:
        event = toolkit_event_from_record(record)
        if (
            self._tracker is not None
            and event.event_type in {"storage_delta", "storage_record"}
        ):
            # Filtering happens at delivery, AFTER classification, so filters
            # on event_type/deposit_origin see any evidence-based promotion and
            # the final origin verdict.
            self._tracker.register(event, raw_message=raw_message)
        else:
            self._deliver(event)

    def _deliver(self, event: BDOEvent) -> None:
        if self.event_filter is not None and not self.event_filter.allows(event):
            return
        if self.on_event is not None:
            self.on_event(event)
        else:
            self._events.append(event)

    def drain_events(self) -> Iterator[BDOEvent]:
        """Yield and remove all currently delivered events."""
        while self._events:
            yield self._events.popleft()

    def flush_stale(self, now: float) -> None:
        if self._tracker is not None:
            self._tracker.flush_stale(now)

    def finalize(self) -> None:
        if self._tracker is not None:
            self._tracker.finalize_all()


def replay_pcap(
    path: str | Path,
    *,
    opcode_profile: str | Path | None = None,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    event_filter: Optional[EventFilter] = None,
    origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
) -> Iterator[BDOEvent]:
    """Replay a pcap/pcapng file and yield structured events.

    ``event_filter=None`` preserves the complete decoded replay stream. Live
    capture has a narrower activity-only default because hydration can contain
    thousands of state records.
    """

    if event_filter is not None and not isinstance(event_filter, EventFilter):
        raise TypeError("event_filter must be an EventFilter or None")
    validated_ports = validate_server_ports(ports)
    collector = _EventCollector(
        server_ports=validated_ports,
        event_filter=event_filter,
        opcode_profile=opcode_profile,
        origin_observer=origin_observer,
    )
    for _ in iter_pcap_file(Path(path), collector.engine):
        yield from collector.drain_events()
    collector.finalize()
    yield from collector.drain_events()


class LiveCaptureSession:
    """Controllable live capture for applications and long-running services.

    ``start()`` begins capture in Scapy's background thread.  Consume events
    with the blocking ``events()`` iterator or the timeout-aware ``poll()``
    method, and call ``stop()`` from the UI/control thread to wake consumers,
    finish TCP reassembly, and finalize pending deposit-origin decisions.

    A session is single-use and supports one event consumer. Create a new
    session when a stopped feature is started again. With ``event_filter=None``
    the session delivers :meth:`EventFilter.activity` events. Pass an explicit
    filter, including ``EventFilter.all()``, to select different semantics.
    """

    _POLL_INTERVAL_SECONDS = 0.2
    _DECODER_STOP_TIMEOUT_SECONDS = 5.0

    def __init__(
        self,
        *,
        opcode_profile: str | Path | None = None,
        live_options: Optional[LiveCaptureOptions] = None,
        event_filter: Optional[EventFilter] = None,
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
    ) -> None:
        if live_options is not None and not isinstance(live_options, LiveCaptureOptions):
            raise TypeError("live_options must be a LiveCaptureOptions or None")
        if event_filter is not None and not isinstance(event_filter, EventFilter):
            raise TypeError("event_filter must be an EventFilter or None")
        resolved_live_options = live_options or LiveCaptureOptions()

        self._opcode_profile = opcode_profile
        self._live_options = resolved_live_options
        self._event_filter = (
            event_filter if event_filter is not None else EventFilter.activity()
        )
        self._origin_observer = origin_observer

        self._queue: Queue[BDOEvent] = Queue(
            maxsize=resolved_live_options.event_queue_size
        )
        self._packet_queue: Queue[object] = Queue(
            maxsize=resolved_live_options.packet_queue_size
        )
        self._tail_events: deque[BDOEvent] = deque()
        self._tail_lock = Lock()
        self._delivery_lock = RLock()
        self._decoder_lock = Lock()
        self._state_lock = Lock()
        self._cleanup_lock = RLock()
        self._stop_requested = Event()
        self._finalizing = Event()
        self._stopped = Event()
        self._started = False
        self._capture: Optional[LivePacketCapture] = None
        self._collector: Optional[_EventCollector] = None
        self._packet_handler: Optional[Callable[[object], None]] = None
        self._packet_worker: Optional[Thread] = None
        self._packet_worker_stop_signaled = False
        self._stop_monitor: Optional[Thread] = None
        self._error: Optional[BaseException] = None
        self._stop_reason: Optional[str] = None
        self._capture_stats = CaptureStats()
        self._packets_accepted = 0
        self._packet_queue_peak = 0
        self._packet_queue_overflows = 0
        self._event_queue_peak = 0
        self._cleanup_incomplete = False

    @property
    def running(self) -> bool:
        capture = self._capture
        return (
            self._started
            and not self._stopped.is_set()
            and capture is not None
            and capture.running
        )

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    @property
    def cleanup_incomplete(self) -> bool:
        """Whether a failed stop retained pipeline ownership for retry."""

        capture = self._capture
        with self._state_lock:
            pipeline_incomplete = self._cleanup_incomplete
        return pipeline_incomplete or (
            capture is not None and capture.cleanup_incomplete
        )

    @property
    def stop_reason(self) -> Optional[str]:
        """Why capture ended: requested, capture-ended, or error."""
        with self._state_lock:
            return self._stop_reason

    @property
    def error(self) -> Optional[BaseException]:
        """First decoder, observer, or cleanup exception, if one occurred."""
        with self._state_lock:
            return self._error

    @property
    def endpoint(self) -> Optional[CaptureEndpoint]:
        """Resolved interface, local address, and packet filter after start."""

        capture = self._capture
        return capture.endpoint if capture is not None else None

    @property
    def health(self) -> LiveCaptureHealth:
        """Return a stable snapshot of live-capture integrity diagnostics."""

        capture = self._capture
        stats = self._capture_stats
        if capture is not None and not capture.stopped:
            # Reading native counters is best-effort and must never turn a
            # diagnostic property into a capture failure.
            try:
                stats = capture.snapshot_stats()
            except BaseException:
                stats = capture.stats
        collector = self._collector
        engine = collector.engine if collector is not None else None
        with self._state_lock:
            return LiveCaptureHealth(
                packets_accepted=self._packets_accepted,
                packet_queue_peak=self._packet_queue_peak,
                packet_queue_overflows=self._packet_queue_overflows,
                event_queue_peak=self._event_queue_peak,
                tcp_gap_resets=int(getattr(engine, "tcp_gap_resets", 0)),
                flow_state_evictions=int(
                    getattr(engine, "flow_state_evictions", 0)
                ),
                pcap_received=stats.received,
                pcap_dropped=stats.dropped,
                pcap_interface_dropped=stats.interface_dropped,
                capture_buffer_bytes=stats.capture_buffer_bytes,
                capture_buffer_fallback=(
                    capture is not None and capture.buffer_error is not None
                ),
            )

    def start(self) -> None:
        """Open capture and hand packets to a bounded decoder worker."""
        with self._cleanup_lock:
            if self._started:
                raise RuntimeError("live capture session was already started")
            collector = _EventCollector(
                server_ports=self._live_options.ports,
                event_filter=self._event_filter,
                on_event=self._enqueue,
                opcode_profile=self._opcode_profile,
                origin_observer=(
                    self._notify_origin_observer
                    if self._origin_observer is not None
                    else None
                ),
            )

            packet_handler = make_packet_handler(collector.engine)
            live_capture = LivePacketCapture(
                capture_options=self._live_options,
                # This callback deliberately performs only one non-blocking
                # queue handoff. Protocol decode and event backpressure live
                # on the worker below, not Scapy's native capture thread.
                on_packet=self._enqueue_packet,
            )
            worker = Thread(
                target=self._run_packet_worker,
                name="bdo-toolkit-items",
                daemon=True,
            )
            self._collector = collector
            self._capture = live_capture
            self._packet_handler = packet_handler
            self._packet_worker = worker
            with self._state_lock:
                self._started = True
                self._stopped.clear()
                self._stop_requested.clear()
                self._finalizing.clear()
            capture_started = False
            try:
                worker.start()
                live_capture.start()
                capture_started = True

                monitor = Thread(
                    target=self._monitor_stop_request,
                    name="bdo-toolkit-items-stop",
                    daemon=True,
                )
                self._stop_monitor = monitor
                monitor.start()
            except BaseException as exc:
                self._rollback_failed_start(
                    exc,
                    capture_started=capture_started,
                )
                raise

    def _rollback_failed_start(
        self,
        error: BaseException,
        *,
        capture_started: bool,
    ) -> None:
        """Release every successfully started owner after startup fails.

        This helper runs while ``_cleanup_lock`` is held. A failed auxiliary
        ``Thread.start()`` is just as transactional as a native startup
        failure: verified cleanup restores the pre-start state; anything that
        cannot be verified remains attached to the original exception for a
        same-session ``stop()`` retry.
        """

        self._finalizing.set()
        self._stop_requested.set()
        capture = self._capture
        cleanup_failures: list[BaseException] = []

        if capture_started and capture is not None and not capture.stopped:
            try:
                self._capture_stats = capture.stop()
            except BaseException as stop_error:
                cleanup_failures.append(stop_error)

        capture_incomplete = capture is not None and (
            capture.cleanup_incomplete
            or (capture_started and not capture.stopped)
        )
        worker = self._packet_worker
        worker_alive = worker is not None and worker.is_alive()

        # A native callback may still race with this session until capture
        # termination is verified. Keep the decoder alive in that case; the
        # stop request makes every later native callback a no-op.
        if not capture_incomplete:
            decoder_deadline = (
                time.monotonic() + self._DECODER_STOP_TIMEOUT_SECONDS
            )
            self._signal_packet_worker_stop(decoder_deadline)
            if (
                worker_alive
                and worker is not None
                and worker is not current_thread()
            ):
                worker.join(
                    timeout=max(0.0, decoder_deadline - time.monotonic())
                )
            worker_alive = worker is not None and worker.is_alive()

        if capture_incomplete or worker_alive:
            self._record_error(error)
            with self._state_lock:
                self._cleanup_incomplete = True
            for failure in cleanup_failures:
                if hasattr(error, "add_note"):
                    error.add_note(
                        "live item capture startup cleanup also failed: "
                        f"{failure!r}"
                    )
            _attach_cleanup_owner(
                error,
                self,
                context="live item capture startup",
            )
            return

        for failure in cleanup_failures:
            if hasattr(error, "add_note"):
                error.add_note(
                    "live item capture startup cleanup reported a fully "
                    f"released error: {failure!r}"
                )
        self._reset_after_failed_start()

    def _reset_after_failed_start(self) -> None:
        """Restore reusable pre-start state after verified rollback."""

        self._collector = None
        self._capture = None
        self._packet_handler = None
        self._packet_worker = None
        self._packet_worker_stop_signaled = False
        self._stop_monitor = None
        self._capture_stats = CaptureStats()
        while True:
            try:
                self._packet_queue.get_nowait()
            except Empty:
                break
        while True:
            try:
                self._queue.get_nowait()
            except Empty:
                break
        with self._tail_lock:
            self._tail_events.clear()
        with self._state_lock:
            self._started = False
            self._error = None
            self._stop_reason = None
            self._cleanup_incomplete = False
            self._packets_accepted = 0
            self._packet_queue_peak = 0
            self._packet_queue_overflows = 0
            self._event_queue_peak = 0
            # Atomic with _started=False so an old request_stop() either wins
            # before rollback and is cleared here, or observes not-started.
            self._stopped.clear()
            self._stop_requested.clear()
            self._finalizing.clear()

    def stop(self) -> None:
        """Stop capture and finalize queued events; safe from a control thread."""
        if (
            self._packet_worker is current_thread()
            or self._inside_origin_observer()
        ):
            raise RuntimeError(
                "stop() cannot block inside the live decoder or origin "
                "observer; use request_stop() instead"
            )
        self._require_started()
        if (
            self._packet_worker is current_thread()
            or self._inside_origin_observer()
        ):
            raise RuntimeError(
                "stop() cannot block inside the live decoder or origin "
                "observer; use request_stop() instead"
            )
        self._finish_stop("requested")

    def request_stop(self) -> None:
        """Request callback-safe shutdown without waiting for finalization."""

        # Deliberately lock-free: a decoder/origin callback must be able to
        # request shutdown while a control thread owns _cleanup_lock and waits
        # for that callback's worker to finish.
        with self._state_lock:
            if not self._started:
                raise RuntimeError("live capture session was not started")
            if self._stopped.is_set():
                return
            # Events produced by packets already accepted before this request
            # remain deliverable while the monitor joins and drains the worker.
            self._finalizing.set()
            self._stop_requested.set()

    def poll(self, timeout: Optional[float] = None) -> Optional[BDOEvent]:
        """Return one event, or ``None`` on timeout or after the final event.

        ``timeout=None`` waits until an event arrives or the session stops.
        Even an indefinite poll wakes promptly when another thread calls
        ``stop()``.
        """
        if self._inside_origin_observer():
            raise RuntimeError(
                "poll() cannot consume events inside origin_observer; "
                "consume them after the callback returns"
            )
        self._require_started()
        _validate_poll_timeout(timeout)
        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            self._service_capture_state()
            try:
                return self._queue.get_nowait()
            except Empty:
                pass

            # Serialize the empty-queue recheck with producers. This lets a
            # non-blocking UI poll safely flush stale origin decisions without
            # racing a producer that fills the one available queue slot.
            with self._delivery_lock:
                try:
                    return self._queue.get_nowait()
                except Empty:
                    pass
                self._flush_stale()
                try:
                    return self._queue.get_nowait()
                except Empty:
                    pass

            if self._stopped.is_set():
                with self._tail_lock:
                    if self._tail_events:
                        return self._tail_events.popleft()
                self.raise_if_failed()
                return None

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                wait_seconds = min(self._POLL_INTERVAL_SECONDS, remaining)
            else:
                wait_seconds = self._POLL_INTERVAL_SECONDS

            try:
                return self._queue.get(timeout=wait_seconds)
            except Empty:
                continue

    def events(self) -> Iterator[BDOEvent]:
        """Return a blocking iterator that ends after ``stop()`` and draining."""
        self._require_started()
        return self._iterate_events()

    def raise_if_failed(self) -> None:
        """Re-raise a background capture failure in the calling thread."""
        error = self.error
        if error is not None:
            raise error

    def _iterate_events(self) -> Iterator[BDOEvent]:
        while True:
            event = self.poll(timeout=self._POLL_INTERVAL_SECONDS)
            if event is not None:
                yield event
            elif self._stopped.is_set():
                return

    def _enqueue_packet(self, packet: object) -> None:
        """Perform the native-callback handoff without blocking Scapy."""

        if self._stop_requested.is_set():
            return
        try:
            self._packet_queue.put_nowait(packet)
        except Full:
            with self._state_lock:
                self._packet_queue_overflows += 1
            self._record_error(
                CaptureIntegrityError(
                    "live packet queue overflowed; the event stream may be incomplete"
                )
            )
            self._stop_requested.set()
            return
        depth = self._packet_queue.qsize()
        with self._state_lock:
            self._packets_accepted += 1
            self._packet_queue_peak = max(self._packet_queue_peak, depth)

    def _run_packet_worker(self) -> None:
        """Decode accepted packets in FIFO order away from capture callback."""

        decode_enabled = True
        while True:
            packet = self._packet_queue.get()
            if packet is _PACKET_WORKER_STOP:
                return
            if not decode_enabled:
                # After decoder state fails, retain deterministic shutdown by
                # draining accepted packets without invoking a corrupt decoder.
                continue
            handler = self._packet_handler
            if handler is None:
                self._record_error(RuntimeError("live packet decoder was unavailable"))
                self._stop_requested.set()
                decode_enabled = False
                continue
            try:
                with self._decoder_lock:
                    handler(packet)
            except BaseException as exc:
                self._record_error(exc)
                self._stop_requested.set()
                decode_enabled = False

    def _monitor_stop_request(self) -> None:
        """Service idle state and stop failures without an active consumer."""

        while not self._stop_requested.wait(self._POLL_INTERVAL_SECONDS):
            capture = self._capture
            capture_error = capture.error if capture is not None else None
            if isinstance(capture_error, BaseException):
                self._record_error(capture_error)
                self._stop_requested.set()
                break
            if capture is not None and not capture.running:
                self._stop_requested.set()
                break
            self._service_engine_clock()
        if not self._stopped.is_set():
            capture = self._capture
            capture_error = capture.error if capture is not None else None
            if isinstance(capture_error, BaseException):
                self._record_error(capture_error)
            reason = (
                "error"
                if self.error is not None
                else "requested"
                if capture is None or capture.running
                else "capture-ended"
            )
            try:
                self._finish_stop(reason)
            except BaseException as exc:
                # A non-cooperative backend remains owned and retryable. The
                # public stop()/poll() paths surface the same retained error;
                # do not leak an unhandled exception from this daemon monitor.
                self._record_error(exc)

    def _service_engine_clock(self) -> None:
        collector = self._collector
        service_gaps = (
            getattr(collector.engine, "service_gaps", None)
            if collector is not None
            else None
        )
        if service_gaps is None:
            return
        try:
            with self._decoder_lock:
                service_gaps(time.time())
        except BaseException as exc:
            self._record_error(exc)
            self._stop_requested.set()

    def _signal_packet_worker_stop(self, deadline: Optional[float] = None) -> bool:
        worker = self._packet_worker
        if worker is None:
            return True
        if self._packet_worker_stop_signaled:
            return True
        if deadline is None:
            deadline = time.monotonic() + self._DECODER_STOP_TIMEOUT_SECONDS
        while worker.is_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                self._packet_queue.put(
                    _PACKET_WORKER_STOP,
                    timeout=min(self._POLL_INTERVAL_SECONDS, remaining),
                )
                self._packet_worker_stop_signaled = True
                return True
            except Full:
                continue
        return True

    def _enqueue(self, event: BDOEvent) -> None:
        # During shutdown the sniffer is joined before the consumer necessarily
        # drains its bounded queue. Route finalized events to a short-lived
        # tail instead of deadlocking the stop caller.
        with self._delivery_lock:
            if self._finalizing.is_set():
                with self._tail_lock:
                    self._tail_events.append(event)
                return
            while not self._stop_requested.is_set():
                try:
                    self._queue.put(event, timeout=self._POLL_INTERVAL_SECONDS)
                    depth = self._queue.qsize()
                    with self._state_lock:
                        self._event_queue_peak = max(
                            self._event_queue_peak,
                            depth,
                        )
                    return
                except Full:
                    if self._finalizing.is_set():
                        with self._tail_lock:
                            self._tail_events.append(event)
                        return

    def _service_capture_state(self) -> None:
        if self._stopped.is_set():
            return
        if self._stop_requested.is_set():
            self._finish_stop("error" if self.error is not None else "requested")
            return
        capture = self._capture
        capture_error = capture.error if capture is not None else None
        if isinstance(capture_error, BaseException):
            self._record_error(capture_error)
            self._finish_stop("error")
            return
        if capture is not None and not capture.running:
            self._finish_stop("error" if self.error is not None else "capture-ended")

    def _flush_stale(self) -> None:
        collector = self._collector
        if collector is None or self._stopped.is_set():
            return
        try:
            collector.flush_stale(time.time())
        except BaseException as exc:
            self._record_error(exc)
            self._stop_requested.set()

    def _finish_stop(self, reason: str) -> None:
        with self._cleanup_lock:
            if self._stopped.is_set():
                return
            self._finalizing.set()
            self._stop_requested.set()
            capture = self._capture
            collector = self._collector

            capture_error = capture.error if capture is not None else None
            if isinstance(capture_error, BaseException):
                self._record_error(capture_error)

            if capture is not None and not capture.stopped:
                stop_failure: Optional[BaseException] = None
                try:
                    self._capture_stats = capture.stop()
                except BaseException as exc:
                    stop_failure = exc
                    self._record_error(exc)
                if not capture.stopped:
                    cleanup_error = (
                        capture.cleanup_error
                        or stop_failure
                        or RuntimeError(
                            "live capture cleanup is incomplete after stop"
                        )
                    )
                    self._record_error(cleanup_error)
                    with self._state_lock:
                        self._cleanup_incomplete = True
                    # Do not queue the worker sentinel or finalize decoder
                    # state while the native callback may still be active.
                    # _stop_requested makes every later callback a no-op.
                    raise cleanup_error
                capture_error = capture.error
                if isinstance(capture_error, BaseException):
                    self._record_error(capture_error)
            elif capture is not None:
                self._capture_stats = capture.stats

            # Capture is joined before the sentinel is queued, so every packet
            # accepted by the callback appears ahead of it in FIFO order.
            decoder_deadline = (
                time.monotonic() + self._DECODER_STOP_TIMEOUT_SECONDS
            )
            self._signal_packet_worker_stop(decoder_deadline)
            worker = self._packet_worker
            if worker is not None and worker.is_alive():
                if worker is not current_thread():
                    worker.join(
                        timeout=max(0.0, decoder_deadline - time.monotonic())
                    )
                if worker.is_alive():
                    cleanup_error = RuntimeError(
                        "live packet decoder cleanup is incomplete after the "
                        f"{self._DECODER_STOP_TIMEOUT_SECONDS:g}-second deadline"
                    )
                    self._record_error(cleanup_error)
                    with self._state_lock:
                        self._cleanup_incomplete = True
                    # The worker may still hold _decoder_lock or call into the
                    # collector. Retain every dependency and retry only after
                    # its termination can be verified.
                    raise cleanup_error
            if collector is not None:
                try:
                    with self._decoder_lock:
                        collector.engine.finish()
                except BaseException as exc:
                    self._record_error(exc)
                try:
                    collector.finalize()
                except BaseException as exc:
                    self._record_error(exc)

            self._packet_handler = None

            with self._state_lock:
                self._stop_reason = "error" if self._error is not None else reason
                self._cleanup_incomplete = False
            self._stopped.set()

    def _record_error(self, error: BaseException) -> None:
        with self._state_lock:
            if self._error is None:
                self._error = error

    def _notify_origin_observer(
        self,
        observation: CompanionObservation,
    ) -> object:
        callback = self._origin_observer
        if callback is None:
            return None
        active_sessions = _ACTIVE_ORIGIN_SESSIONS.get()
        token = _ACTIVE_ORIGIN_SESSIONS.set(active_sessions + (self,))
        try:
            return callback(observation)
        finally:
            _ACTIVE_ORIGIN_SESSIONS.reset(token)

    def _inside_origin_observer(self) -> bool:
        return self in _ACTIVE_ORIGIN_SESSIONS.get()

    def _require_started(self) -> None:
        # Startup and verified rollback both mutate ``_started`` under the
        # cleanup lock. Waiting here prevents a concurrent stop/poll from
        # observing the provisional True and acting on a rolled-back session.
        with self._cleanup_lock:
            with self._state_lock:
                if not self._started:
                    raise RuntimeError("live capture session was not started")

    def __enter__(self) -> "LiveCaptureSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._started and not self._stopped.is_set():
            try:
                self.stop()
            except BaseException as cleanup_error:
                if exc_value is None:
                    raise
                if self.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc_value,
                        self,
                        context="live item capture context",
                    )
                if hasattr(exc_value, "add_note"):
                    exc_value.add_note(
                        "live item capture context cleanup also failed: "
                        f"{cleanup_error!r}"
                    )


def capture_live(
    *,
    opcode_profile: str | Path | None = None,
    live_options: Optional[LiveCaptureOptions] = None,
    event_filter: Optional[EventFilter] = None,
    capture_seconds: Optional[float] = None,
    origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
) -> Iterator[BDOEvent]:
    """Start passive live capture and yield structured events.

    This blocking convenience wrapper is intended for scripts. Applications
    that need programmatic start/stop control should use
    :class:`LiveCaptureSession`. When ``event_filter`` is omitted, only
    :meth:`EventFilter.activity` events are delivered; pass
    ``EventFilter.all()`` for the complete decoded stream.
    """
    _validate_capture_seconds(capture_seconds)
    session = LiveCaptureSession(
        opcode_profile=opcode_profile,
        live_options=live_options,
        event_filter=event_filter,
        origin_observer=origin_observer,
    )
    session.start()
    started_at = time.monotonic()
    deadline_timer: Optional[Timer] = None
    if capture_seconds is not None:
        # The deadline belongs to capture ownership, not generator progress.
        # It therefore fires even while the consumer is suspended after a
        # yielded event.
        def finish_at_deadline() -> None:
            try:
                session._finish_stop("timeout")
            except BaseException as exc:
                # _finish_stop has retained both the first error and every
                # owner required for a retry. Avoid an unhandled Timer-thread
                # traceback while the generator remains the public owner.
                session._record_error(exc)

        try:
            deadline_timer = Timer(capture_seconds, finish_at_deadline)
            deadline_timer.name = "bdo-toolkit-items-deadline"
            deadline_timer.daemon = True
            deadline_timer.start()
        except BaseException as exc:
            if deadline_timer is not None:
                deadline_timer.cancel()
            try:
                session.stop()
            except BaseException as cleanup_error:
                if session.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc,
                        session,
                        context="timed live item capture startup",
                    )
                if hasattr(exc, "add_note"):
                    exc.add_note(
                        "timed live item capture startup cleanup also "
                        f"failed: {cleanup_error!r}"
                    )
            raise
    try:
        while True:
            if capture_seconds is None:
                poll_timeout = LiveCaptureSession._POLL_INTERVAL_SECONDS
            else:
                remaining = capture_seconds - (time.monotonic() - started_at)
                if remaining <= 0:
                    session._finish_stop("timeout")
                    poll_timeout = 0.0
                else:
                    poll_timeout = min(
                        LiveCaptureSession._POLL_INTERVAL_SECONDS,
                        remaining,
                    )

            event = session.poll(timeout=poll_timeout)
            if event is not None:
                yield event
            elif session.stopped:
                break
    finally:
        if deadline_timer is not None:
            deadline_timer.cancel()
        # No yields during generator close. The session finalizes pending TCP
        # and origin state; a normal stop path drains it in the loop above.
        if not session.stopped:
            try:
                session.stop()
            except BaseException as exc:
                if session.cleanup_incomplete:
                    _attach_cleanup_owner(
                        exc,
                        session,
                        context="live item capture convenience wrapper",
                    )
                raise


def _validate_poll_timeout(value: Optional[float]) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("timeout must be a number or None")
    if not math.isfinite(value) or value < 0:
        raise ValueError("timeout must be finite and non-negative")


def _validate_capture_seconds(value: Optional[float]) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("capture_seconds must be a number or None")
    if not math.isfinite(value) or value < 0:
        raise ValueError("capture_seconds must be finite and non-negative")
