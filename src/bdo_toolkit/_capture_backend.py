"""Scapy-backed packet sources for live capture and pcap replay."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Protocol


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
        # The toolkit only needs IPv4. Disabling IPv6 before importing the
        # IPv4 layers also avoids unnecessary route discovery on startup.
        from scapy.config import conf  # type: ignore

        conf.ipv6_enabled = False

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
    port_expression = " or ".join(f"src port {port}" for port in ports)
    bpf_filter = f"tcp and ({port_expression})"
    if local_ip is not None:
        bpf_filter += f" and dst host {local_ip}"
    return bpf_filter


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


def replay_pcap_file(path: Path, engine: SegmentConsumer) -> None:
    _, _, _, _, PcapReader = import_scapy()
    handler = make_packet_handler(engine)

    if not path.is_file():
        raise FileNotFoundError(f"Capture file does not exist: {path}")

    try:
        with PcapReader(str(path)) as packets:
            for packet in packets:
                handler(packet)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read capture {path}: {exc}") from exc

    engine.finish()
