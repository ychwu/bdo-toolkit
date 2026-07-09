"""Scapy-backed packet sources for live capture and pcap replay."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional, Protocol


class SegmentConsumer(Protocol):
    """Anything that accepts TCP segments (PacketEngine, FlowManager)."""

    def process_tcp_segment(
        self,
        *,
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        sequence: int,
        payload: bytes,
        timestamp: float,
        syn: bool = False,
        rst: bool = False,
        fin: bool = False,
    ) -> None: ...

    def finish(self) -> None: ...


@dataclass(frozen=True)
class CaptureTarget:
    interface: Optional[str]
    local_ip: Optional[str]
    gateway: Optional[str]


def import_scapy():
    try:
        from scapy.interfaces import get_if_list  # type: ignore
        from scapy.layers.inet import IP, TCP  # type: ignore
        from scapy.sendrecv import sniff  # type: ignore
        from scapy.utils import PcapReader  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for packet capture and pcap replay. "
            "Install it with: pip install scapy"
        ) from exc
    return IP, TCP, get_if_list, sniff, PcapReader


def detect_default_capture_target() -> CaptureTarget:
    try:
        from scapy.config import conf  # type: ignore

        route = conf.route.route("8.8.8.8")
    except Exception:
        return CaptureTarget(interface=None, local_ip=None, gateway=None)

    interface = str(route[0]) if len(route) > 0 and route[0] else None
    local_ip = str(route[1]) if len(route) > 1 and route[1] else None
    gateway = str(route[2]) if len(route) > 2 and route[2] else None

    if local_ip in {None, "0.0.0.0"}:
        local_ip = None
    if gateway in {None, "0.0.0.0"}:
        gateway = None

    return CaptureTarget(interface=interface, local_ip=local_ip, gateway=gateway)


def build_bpf_filter(ports: Iterable[int], local_ip: Optional[str] = None) -> str:
    normalized_ports = validate_server_ports(ports)
    port_expression = " or ".join(f"src port {port}" for port in normalized_ports)
    bpf_filter = f"tcp and ({port_expression})"
    if local_ip is not None:
        bpf_filter += f" and dst host {local_ip}"
    return bpf_filter


def validate_server_ports(ports: Iterable[int]) -> tuple[int, ...]:
    """Return unique validated TCP ports, preserving caller order."""
    normalized: list[int] = []
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError(f"server port must be an integer, got {port!r}")
        if not 1 <= port <= 65535:
            raise ValueError(f"server port out of range: {port}")
        if port not in normalized:
            normalized.append(port)
    if not normalized:
        raise ValueError("at least one server port is required")
    return tuple(normalized)


def make_packet_handler(engine: SegmentConsumer):
    IP, TCP, _, _, _ = import_scapy()

    def handle(packet) -> None:
        if IP not in packet or TCP not in packet:
            return

        ip = packet[IP]
        tcp = packet[TCP]
        payload = bytes(tcp.payload)
        flags = int(tcp.flags)

        engine.process_tcp_segment(
            source_ip=str(ip.src),
            source_port=int(tcp.sport),
            destination_ip=str(ip.dst),
            destination_port=int(tcp.dport),
            sequence=int(tcp.seq),
            payload=payload,
            timestamp=float(packet.time),
            syn=bool(flags & 0x02),
            rst=bool(flags & 0x04),
            fin=bool(flags & 0x01),
        )

    return handle


def iter_pcap_file(path: Path, engine: SegmentConsumer) -> Iterator[None]:
    """Process one capture packet at a time, yielding after each packet.

    The yield point lets public replay drain decoded events incrementally
    instead of retaining the entire capture's results in memory.
    """
    _, _, _, _, PcapReader = import_scapy()
    from scapy.error import Scapy_Exception  # type: ignore

    handler = make_packet_handler(engine)

    if not path.is_file():
        raise FileNotFoundError(f"Capture file does not exist: {path}")

    source = None
    packets = None
    try:
        # Passing our own handle lets us close it even when PcapReader's
        # constructor rejects the file.  Some Scapy versions otherwise leave
        # invalid captures locked on Windows.
        source = path.open("rb")
        packets = PcapReader(source)
        for packet in packets:
            handler(packet)
            yield None
    except (OSError, ValueError, Scapy_Exception) as exc:
        raise ValueError(f"Could not read capture {path}: {exc}") from exc
    finally:
        if packets is not None:
            packets.close()
        if source is not None:
            source.close()

    engine.finish()


def replay_pcap_file(path: Path, engine: SegmentConsumer) -> None:
    """Process an entire capture file eagerly (calibration convenience)."""
    for _ in iter_pcap_file(path, engine):
        pass
