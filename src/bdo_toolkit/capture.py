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
from ._engine import PacketEngine, toolkit_event_from_record
from ._protocol import DEFAULT_SERVER_PORTS, LootEvent
from ._specs import select_event_specs
from .events import BDOEvent
from .filters import EventFilter
from .profiles import default_profile_path


class _EventCollector:
    """Wire a PacketEngine to app-facing events with optional filtering."""

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
        self.engine = PacketEngine(
            server_ports=server_ports,
            event_specs=event_specs,
            on_event=self._handle_record,
        )

    def _handle_record(self, record: LootEvent, raw_message: bytes) -> None:
        event = toolkit_event_from_record(record)
        if self.event_filter is not None and not self.event_filter.allows(event):
            return
        self.events.append(event)
        if self.on_event is not None:
            self.on_event(event)


def _event_filter(
    *,
    event_types: Optional[Iterable[str]] = None,
    sources: Optional[Iterable[str]] = None,
    item_ids: Optional[Iterable[int]] = None,
) -> Optional[EventFilter]:
    if event_types is None and sources is None and item_ids is None:
        return None
    return EventFilter.from_values(
        event_types=event_types,
        sources=sources,
        item_ids=item_ids,
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
        ),
        opcode_profile=opcode_profile,
        include_legacy_opcodes=include_legacy_opcodes,
        ignore_opcode_profile=ignore_opcode_profile,
    )
    replay_pcap_file(Path(path), collector.engine)
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
                if not live_capture.running:
                    break
    finally:
        if live_capture.running:
            live_capture.stop()
        collector.engine.finish()
