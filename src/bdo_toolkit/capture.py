"""Packet capture and pcap replay APIs."""

from __future__ import annotations

import time
from pathlib import Path
from queue import Empty, Queue
from typing import Callable, Iterable, Iterator, Optional

from ._capture_backend import (
    build_bpf_filter,
    detect_default_capture_target,
    import_scapy,
    make_packet_handler,
    replay_pcap_file,
)
from ._deposit_origin import DecrementSpec, DepositOriginTracker
from ._engine import PacketEngine, toolkit_event_from_record
from ._protocol import (
    DEFAULT_SERVER_PORTS,
    DEPOSIT_DECREMENT_FALLBACK_OPCODES,
    LootEvent,
)
from ._specs import ProfileError, _parse_opcode, select_event_specs
from .events import BDOEvent
from .filters import EventFilter
from .profiles import default_profile_path, load_opcode_profile


def _decrement_specs(
    profile_path: Path,
    ignore_opcode_profile: bool,
) -> tuple[DecrementSpec, ...]:
    """Source-stack-decrement shapes: calibrated profile entries + fallbacks."""
    specs = [DecrementSpec(opcode) for opcode in DEPOSIT_DECREMENT_FALLBACK_OPCODES]
    if not ignore_opcode_profile:
        try:
            profile = load_opcode_profile(profile_path)
        except (OSError, ValueError, ProfileError):
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
    ) -> None:
        profile_path = (
            Path(opcode_profile) if opcode_profile is not None else default_profile_path()
        )
        event_specs, profile_source = select_event_specs(
            opcodes_path=profile_path,
            include_legacy=include_legacy_opcodes,
            ignore_opcodes=ignore_opcode_profile,
        )
        self.events: list[BDOEvent] = []
        self.event_filter = event_filter
        self.on_event = on_event
        self.profile_source = profile_source
        self._tracker = DepositOriginTracker(
            decrement_specs=_decrement_specs(profile_path, ignore_opcode_profile),
            emit=self._deliver,
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
        self.events.append(event)
        if self.on_event is not None:
            self.on_event(event)

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
) -> Iterator[BDOEvent]:
    """Replay a pcap/pcapng file and yield structured events.

    ``quiet`` is retained for backwards compatibility; the native replay engine
    produces no console output either way.
    """

    collector = _EventCollector(
        server_ports=ports,
        event_filter=_event_filter(
            event_types=event_types,
            sources=sources,
            item_ids=item_ids,
            deposit_origins=deposit_origins,
        ),
        opcode_profile=opcode_profile,
        include_legacy_opcodes=include_legacy_opcodes,
        ignore_opcode_profile=ignore_opcode_profile,
    )
    replay_pcap_file(Path(path), collector.engine)
    collector.finalize()
    yield from collector.events


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
) -> Iterator[BDOEvent]:
    """Start passive live capture and yield structured events.

    The core decoder can parse all known event categories in one session. The
    optional filters control what reaches the application.
    """

    IP, TCP, _, _, _ = import_scapy()
    from scapy.sendrecv import AsyncSniffer  # type: ignore

    queue: Queue[BDOEvent] = Queue()
    collector = _EventCollector(
        server_ports=ports,
        event_filter=_event_filter(
            event_types=event_types,
            sources=sources,
            item_ids=item_ids,
            deposit_origins=deposit_origins,
        ),
        on_event=queue.put,
        opcode_profile=opcode_profile,
        include_legacy_opcodes=include_legacy_opcodes,
        ignore_opcode_profile=ignore_opcode_profile,
    )

    detected_target = detect_default_capture_target()
    capture_interface = interface or detected_target.interface
    capture_local_ip = local_ip
    if capture_local_ip is None and interface is None and not no_local_ip_filter:
        capture_local_ip = detected_target.local_ip

    bpf_filter = None if no_bpf else build_bpf_filter(ports, capture_local_ip)
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
    live_capture.start()
    started_at = time.monotonic()
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
        if live_capture.running:
            live_capture.stop()
        collector.engine.finish()
        collector.finalize()
    # Normal end of capture: deliver storage deltas finalized during cleanup.
    while True:
        try:
            yield queue.get_nowait()
        except Empty:
            break
