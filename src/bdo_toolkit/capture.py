"""Packet capture and pcap replay APIs."""

from __future__ import annotations

import contextlib
import io
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Iterable, Iterator, Optional

from .events import BDOEvent
from .filters import EventFilter
from .legacy_bridge import ToolkitLootSniffer, legacy_parser

DEFAULT_SERVER_PORTS = (8884, 8885, 8889)


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
    """Replay a pcap/pcapng file and yield structured events."""

    legacy = legacy_parser()
    bridge = ToolkitLootSniffer(
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
    output = io.StringIO()
    stdout_context = contextlib.redirect_stdout(output) if quiet else contextlib.nullcontext()
    with stdout_context:
        legacy.run_offline(Path(path), bridge.sniffer)
    yield from bridge.events


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

    legacy = legacy_parser()
    IP, TCP, _, _, _ = legacy.import_scapy()
    from scapy.sendrecv import AsyncSniffer  # type: ignore

    queue: Queue[BDOEvent] = Queue()
    bridge = ToolkitLootSniffer(
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

    detected_target = legacy.detect_default_capture_target()
    capture_interface = interface or detected_target.interface
    capture_local_ip = local_ip
    if capture_local_ip is None and interface is None and not no_local_ip_filter:
        capture_local_ip = detected_target.local_ip

    bpf_filter = None if no_bpf else legacy.build_bpf_filter(ports, capture_local_ip)
    lfilter = None
    if no_bpf:
        lfilter = lambda packet: (  # noqa: E731
            IP in packet
            and TCP in packet
            and int(packet[TCP].sport) in bridge.sniffer.server_ports
            and (
                capture_local_ip is None
                or str(packet[IP].dst) == capture_local_ip
            )
        )

    live_capture = AsyncSniffer(
        iface=capture_interface,
        filter=bpf_filter,
        lfilter=lfilter,
        prn=legacy.make_packet_handler(bridge.sniffer),
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
        bridge.sniffer.finish()

