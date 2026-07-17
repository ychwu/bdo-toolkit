"""Packet capture and pcap replay APIs."""

from __future__ import annotations

from collections import deque
import math
import time
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, RLock
from typing import Any, Callable, Iterator, Optional

from ._capture_backend import (
    build_bpf_filter,
    detect_default_capture_target,
    import_scapy,
    iter_pcap_file,
    make_packet_handler,
    validate_server_ports,
)
from ._capture_options import LiveCaptureOptions
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
    """Position-exact source-stack-decrement shapes from the active profile."""
    specs: list[DecrementSpec] = []
    for entry in profile.specs.get("SOURCE_STACK_DECREMENT", []):
        opcode = _parse_opcode(entry.get("opcode"))
        length = entry.get("length")
        offset = entry.get("quantity_removed_offset")
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
            specs.append(DecrementSpec(opcode, length, offset))
    return tuple(specs)


def _origin_companion_families(
    profile: OpcodeProfile,
) -> tuple[OriginCompanionFamily, ...]:
    return profile.origin_companion_families


class _EventCollector:
    """Wire a PacketEngine to app-facing events with optional filtering.

    storage_delta events take a short detour through the deposit-origin
    tracker (a few frames of lookahead) so each event carries a classified
    ``deposit_origin``; all other events emit immediately, which can
    place a deferred storage_delta slightly after later events of other
    types. Timestamps are unaffected.
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
        self._tracker = DepositOriginTracker(
            decrement_specs=_decrement_specs(profile),
            emit=self._deliver,
            origin_observer=origin_observer,
            known_companion_families=_origin_companion_families(profile),
        )
        self.engine = PacketEngine(
            server_ports=server_ports,
            event_specs=loaded_specs.specs,
            on_event=self._handle_record,
            frame_observer=self._tracker.observe_frame,
            stream_observer=self._tracker.observe_stream,
        )

    def _handle_record(self, record: LootEvent, raw_message: bytes) -> None:
        event = toolkit_event_from_record(record)
        if event.event_type == "storage_delta":
            # Filtering happens at delivery, AFTER classification, so filters
            # on deposit_origin see the final field value.
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
        self._tracker.flush_stale(now)

    def finalize(self) -> None:
        self._tracker.finalize_all()


def replay_pcap(
    path: str | Path,
    *,
    opcode_profile: str | Path | None = None,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    event_filter: Optional[EventFilter] = None,
    origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
) -> Iterator[BDOEvent]:
    """Replay a pcap/pcapng file and yield structured events."""

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
    session when a stopped feature is started again.
    """

    _POLL_INTERVAL_SECONDS = 0.2

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
        self._event_filter = event_filter
        self._origin_observer = origin_observer

        self._queue: Queue[BDOEvent] = Queue(
            maxsize=resolved_live_options.event_queue_size
        )
        self._tail_events: deque[BDOEvent] = deque()
        self._tail_lock = Lock()
        self._delivery_lock = RLock()
        self._state_lock = Lock()
        self._cleanup_lock = Lock()
        self._stop_requested = Event()
        self._finalizing = Event()
        self._stopped = Event()
        self._capture_ready = Event()
        self._started = False
        self._capture: Any = None
        self._collector: Optional[_EventCollector] = None
        self._error: Optional[BaseException] = None
        self._stop_reason: Optional[str] = None

    @property
    def running(self) -> bool:
        capture = self._capture
        capture_thread = getattr(capture, "thread", None)
        thread_finished = (
            capture_thread is not None
            and capture_thread.ident is not None
            and not capture_thread.is_alive()
        )
        return (
            self._started
            and not self._stopped.is_set()
            and capture is not None
            and not thread_finished
            and (not self._capture_ready.is_set() or bool(capture.running))
        )

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

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

    def start(self) -> None:
        """Open the capture handle, then process packets in the background."""
        with self._cleanup_lock:
            if self._started:
                raise RuntimeError("live capture session was already started")
            self._capture_ready.clear()

            IP, TCP, _, _, _ = import_scapy()
            from scapy.sendrecv import AsyncSniffer  # type: ignore

            collector = _EventCollector(
                server_ports=self._live_options.ports,
                event_filter=self._event_filter,
                on_event=self._enqueue,
                opcode_profile=self._opcode_profile,
                origin_observer=self._origin_observer,
            )

            detected_target = None
            if self._live_options.interface is None:
                detected_target = detect_default_capture_target()
                capture_interface = detected_target.interface
            else:
                capture_interface = self._live_options.interface
            capture_local_ip = self._live_options.local_ip
            if (
                capture_local_ip is None
                and self._live_options.interface is None
                and self._live_options.auto_local_ip
            ):
                assert detected_target is not None
                capture_local_ip = detected_target.local_ip

            bpf_filter = (
                None
                if not self._live_options.use_bpf
                else build_bpf_filter(self._live_options.ports, capture_local_ip)
            )
            lfilter = None
            if not self._live_options.use_bpf:
                lfilter = lambda packet: (  # noqa: E731
                    IP in packet
                    and TCP in packet
                    and int(packet[TCP].sport) in collector.engine.server_ports
                    and (
                        capture_local_ip is None
                        or str(packet[IP].dst) == capture_local_ip
                    )
                )

            packet_handler = make_packet_handler(collector.engine)

            def handle_packet(packet: object) -> None:
                try:
                    packet_handler(packet)
                except BaseException as exc:
                    self._record_error(exc)
                    self._stop_requested.set()
                    # Scapy catches callback exceptions and closes the failed
                    # capture socket. Preserve that behavior while retaining
                    # the exception for the public consumer.
                    raise

            live_capture = AsyncSniffer(
                iface=capture_interface,
                filter=bpf_filter,
                lfilter=lfilter,
                prn=handle_packet,
                store=False,
                started_callback=self._capture_ready.set,
            )
            self._collector = collector
            self._capture = live_capture
            self._started = True
            try:
                live_capture.start()
                # AsyncSniffer.start() returns before its thread necessarily
                # opens the adapter. Do not return a session that can race an
                # immediate Stop click; wait until its started callback fires
                # or its thread reports a startup failure.
                while not self._capture_ready.wait(timeout=0.05):
                    capture_error = getattr(live_capture, "exception", None)
                    if isinstance(capture_error, BaseException):
                        raise capture_error
                    capture_thread = getattr(live_capture, "thread", None)
                    if (
                        capture_thread is not None
                        and capture_thread.ident is not None
                        and not capture_thread.is_alive()
                    ):
                        raise RuntimeError("live capture thread ended during startup")
            except BaseException:
                if live_capture.running:
                    try:
                        live_capture.stop()
                    except BaseException:
                        pass
                self._collector = None
                self._capture = None
                self._started = False
                self._capture_ready.clear()
                raise

    def stop(self) -> None:
        """Stop capture and finalize queued events; safe from a control thread."""
        self._require_started()
        self._finish_stop("requested")

    def poll(self, timeout: Optional[float] = None) -> Optional[BDOEvent]:
        """Return one event, or ``None`` on timeout or after the final event.

        ``timeout=None`` waits until an event arrives or the session stops.
        Even an indefinite poll wakes promptly when another thread calls
        ``stop()``.
        """
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
        capture_error = getattr(capture, "exception", None)
        if isinstance(capture_error, BaseException):
            self._record_error(capture_error)
            self._finish_stop("error")
            return
        capture_thread = getattr(capture, "thread", None)
        thread_finished = (
            capture_thread is not None
            and capture_thread.ident is not None
            and not capture_thread.is_alive()
        )
        if capture is not None and (
            (self._capture_ready.is_set() and not bool(capture.running))
            or thread_finished
        ):
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

            capture_error = getattr(capture, "exception", None)
            if isinstance(capture_error, BaseException):
                self._record_error(capture_error)

            if capture is not None and capture.running:
                try:
                    capture.stop()
                except BaseException as exc:
                    self._record_error(exc)
            if collector is not None:
                try:
                    collector.engine.finish()
                except BaseException as exc:
                    self._record_error(exc)
                try:
                    collector.finalize()
                except BaseException as exc:
                    self._record_error(exc)

            with self._state_lock:
                self._stop_reason = "error" if self._error is not None else reason
            self._stopped.set()

    def _record_error(self, error: BaseException) -> None:
        with self._state_lock:
            if self._error is None:
                self._error = error

    def _require_started(self) -> None:
        if not self._started:
            raise RuntimeError("live capture session was not started")

    def __enter__(self) -> "LiveCaptureSession":
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._started and not self._stopped.is_set():
            self.stop()


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
    :class:`LiveCaptureSession`.
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
        # No yields during generator close. The session finalizes pending TCP
        # and origin state; a normal stop path drains it in the loop above.
        if not session.stopped:
            session.stop()


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
