"""Packet capture and pcap replay APIs."""

from __future__ import annotations

from collections import deque
import ipaddress
import math
import time
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event
from typing import Callable, Iterable, Iterator, Optional

from ._capture_backend import (
    build_bpf_filter,
    detect_default_capture_target,
    import_scapy,
    iter_pcap_file,
    make_packet_handler,
    validate_server_ports,
)
from ._deposit_origin import DecrementSpec, DepositOriginTracker
from ._engine import PacketEngine, toolkit_event_from_record
from ._protocol import (
    DEFAULT_SERVER_PORTS,
    DEPOSIT_DECREMENT_FALLBACK_OPCODES,
    LootEvent,
)
from ._specs import _parse_opcode, select_event_specs
from .events import BDOEvent
from .filters import EventFilter
from .origin_learning import CompanionObservation
from .profiles import (
    OriginCompanionFamily,
    default_profile_path,
    load_opcode_profile,
)


def _decrement_specs(
    profile_path: Path,
    ignore_opcode_profile: bool,
) -> tuple[DecrementSpec, ...]:
    """Source-stack-decrement shapes: calibrated profile entries + fallbacks."""
    specs = [DecrementSpec(opcode) for opcode in DEPOSIT_DECREMENT_FALLBACK_OPCODES]
    if not ignore_opcode_profile:
        try:
            profile = load_opcode_profile(profile_path)
        except (OSError, ValueError):
            return tuple(specs)
        for entry in profile.specs.get("SOURCE_STACK_DECREMENT", []):
            opcode = _parse_opcode(entry.get("opcode"))
            offset = entry.get("quantity_removed_offset")
            if opcode is not None:
                specs.append(
                    DecrementSpec(
                        opcode,
                        offset if isinstance(offset, int) and offset >= 0 else None,
                    )
                )
    return tuple(specs)


def _origin_companion_families(
    profile_path: Path,
    ignore_opcode_profile: bool,
) -> tuple[OriginCompanionFamily, ...]:
    if ignore_opcode_profile:
        return ()
    try:
        return load_opcode_profile(profile_path).origin_companion_families
    except (OSError, ValueError):
        return ()


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
        include_legacy_opcodes: bool = False,
        ignore_opcode_profile: bool = False,
        origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
    ) -> None:
        profile_path = (
            Path(opcode_profile) if opcode_profile is not None else default_profile_path()
        )
        event_specs, profile_source = select_event_specs(
            opcodes_path=profile_path,
            include_legacy=include_legacy_opcodes,
            ignore_opcodes=ignore_opcode_profile,
            require_profile=opcode_profile is not None,
        )
        self._events: deque[BDOEvent] = deque()
        self.event_filter = event_filter
        self.on_event = on_event
        self.profile_source = profile_source
        self._tracker = DepositOriginTracker(
            decrement_specs=_decrement_specs(profile_path, ignore_opcode_profile),
            emit=self._deliver,
            origin_observer=origin_observer,
            known_companion_families=_origin_companion_families(
                profile_path,
                ignore_opcode_profile,
            ),
        )
        self.engine = PacketEngine(
            server_ports=server_ports,
            event_specs=event_specs,
            on_event=self._handle_record,
            frame_observer=self._tracker.observe_frame,
        )

    def _handle_record(self, record: LootEvent, raw_message: bytes) -> None:
        event = toolkit_event_from_record(record)
        if event.event_type == "storage_delta":
            # Filtering happens at delivery, AFTER classification, so filters
            # on deposit_origin see the final field value.
            self._tracker.register(event)
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


def _event_filter(
    *,
    event_types: Optional[Iterable[str]] = None,
    sources: Optional[Iterable[str]] = None,
    item_ids: Optional[Iterable[int]] = None,
    deposit_origins: Optional[Iterable[str]] = None,
) -> Optional[EventFilter]:
    if (
        event_types is None
        and sources is None
        and item_ids is None
        and deposit_origins is None
    ):
        return None
    return EventFilter.from_values(
        event_types=event_types,
        sources=sources,
        item_ids=item_ids,
        deposit_origins=deposit_origins,
    )


def replay_pcap(
    path: str | Path,
    *,
    opcode_profile: str | Path | None = None,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    include_legacy_opcodes: bool = False,
    ignore_opcode_profile: bool = False,
    event_types: Optional[Iterable[str]] = None,
    sources: Optional[Iterable[str]] = None,
    item_ids: Optional[Iterable[int]] = None,
    deposit_origins: Optional[Iterable[str]] = None,
    quiet: bool = True,
    origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
) -> Iterator[BDOEvent]:
    """Replay a pcap/pcapng file and yield structured events.

    ``quiet`` is retained for backwards compatibility; the native replay engine
    produces no console output either way.
    """

    validated_ports = validate_server_ports(ports)
    collector = _EventCollector(
        server_ports=validated_ports,
        event_filter=_event_filter(
            event_types=event_types,
            sources=sources,
            item_ids=item_ids,
            deposit_origins=deposit_origins,
        ),
        opcode_profile=opcode_profile,
        include_legacy_opcodes=include_legacy_opcodes,
        ignore_opcode_profile=ignore_opcode_profile,
        origin_observer=origin_observer,
    )
    for _ in iter_pcap_file(Path(path), collector.engine):
        yield from collector.drain_events()
    collector.finalize()
    yield from collector.drain_events()


def capture_live(
    *,
    opcode_profile: str | Path | None = None,
    interface: Optional[str] = None,
    local_ip: Optional[str] = None,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
    include_legacy_opcodes: bool = False,
    ignore_opcode_profile: bool = False,
    event_types: Optional[Iterable[str]] = None,
    sources: Optional[Iterable[str]] = None,
    item_ids: Optional[Iterable[int]] = None,
    deposit_origins: Optional[Iterable[str]] = None,
    capture_seconds: Optional[float] = None,
    no_bpf: bool = False,
    no_local_ip_filter: bool = False,
    event_queue_size: int = 1024,
    origin_observer: Optional[Callable[[CompanionObservation], object]] = None,
) -> Iterator[BDOEvent]:
    """Start passive live capture and yield structured events.

    The core decoder can parse all known event categories in one session. The
    optional filters control what reaches the application.
    """

    validated_ports = validate_server_ports(ports)
    _validate_capture_seconds(capture_seconds)
    if isinstance(event_queue_size, bool) or not isinstance(event_queue_size, int):
        raise ValueError("event_queue_size must be an integer")
    if event_queue_size <= 0:
        raise ValueError("event_queue_size must be greater than zero")
    if local_ip is not None:
        try:
            local_ip = str(ipaddress.IPv4Address(local_ip))
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"local_ip must be an IPv4 address: {local_ip!r}") from exc

    IP, TCP, _, _, _ = import_scapy()
    from scapy.sendrecv import AsyncSniffer  # type: ignore

    queue: Queue[BDOEvent] = Queue(maxsize=event_queue_size)
    stop_requested = Event()
    finalizing = Event()
    tail_events: deque[BDOEvent] = deque()

    def enqueue(event: BDOEvent) -> None:
        # During shutdown the sniffer is joined before the generator can drain
        # its queue. Route final events to a short-lived tail instead of
        # deadlocking on a full bounded queue.
        if finalizing.is_set():
            tail_events.append(event)
            return
        while not stop_requested.is_set():
            try:
                queue.put(event, timeout=0.2)
                return
            except Full:
                if finalizing.is_set():
                    tail_events.append(event)
                    return
                continue

    collector = _EventCollector(
        server_ports=validated_ports,
        event_filter=_event_filter(
            event_types=event_types,
            sources=sources,
            item_ids=item_ids,
            deposit_origins=deposit_origins,
        ),
        on_event=enqueue,
        opcode_profile=opcode_profile,
        include_legacy_opcodes=include_legacy_opcodes,
        ignore_opcode_profile=ignore_opcode_profile,
        origin_observer=origin_observer,
    )

    detected_target = None
    if interface is None:
        detected_target = detect_default_capture_target()
        capture_interface = detected_target.interface
    else:
        capture_interface = interface
    capture_local_ip = local_ip
    if capture_local_ip is None and interface is None and not no_local_ip_filter:
        assert detected_target is not None
        capture_local_ip = detected_target.local_ip

    bpf_filter = (
        None if no_bpf else build_bpf_filter(validated_ports, capture_local_ip)
    )
    lfilter = None
    if no_bpf:
        lfilter = lambda packet: (  # noqa: E731
            IP in packet
            and TCP in packet
            and int(packet[TCP].sport) in collector.engine.server_ports
            and (
                capture_local_ip is None
                or str(packet[IP].dst) == capture_local_ip
            )
        )

    live_capture = AsyncSniffer(
        iface=capture_interface,
        filter=bpf_filter,
        lfilter=lfilter,
        prn=make_packet_handler(collector.engine),
        store=False,
    )
    try:
        live_capture.start()
    except BaseException:
        if live_capture.running:
            live_capture.stop()
        raise
    started_at = time.monotonic()
    cleaned_up = False

    def cleanup() -> None:
        nonlocal cleaned_up
        if cleaned_up:
            return
        cleaned_up = True
        finalizing.set()
        stop_requested.set()
        if live_capture.running:
            live_capture.stop()
        collector.engine.finish()
        collector.finalize()

    try:
        while True:
            if capture_seconds is not None:
                elapsed = time.monotonic() - started_at
                if elapsed >= capture_seconds:
                    break
            try:
                yield queue.get(timeout=0.2)
            except Empty:
                collector.flush_stale(time.time())
                if not live_capture.running:
                    break
    finally:
        # No yields in here: a consumer that stops iterating early closes the
        # generator, and yielding during that close is a RuntimeError.
        cleanup()
    # Normal end of capture: deliver events queued before shutdown, followed
    # by storage deltas and drained TCP events finalized during cleanup.
    while True:
        try:
            yield queue.get_nowait()
        except Empty:
            break
    yield from tail_events


def _validate_capture_seconds(value: Optional[float]) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("capture_seconds must be a number or None")
    if not math.isfinite(value) or value < 0:
        raise ValueError("capture_seconds must be finite and non-negative")
