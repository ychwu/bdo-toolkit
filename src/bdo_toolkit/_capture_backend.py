"""Scapy-backed packet sources for live capture and pcap replay."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Protocol


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


def _required_header_integer(value: Any, field_name: str) -> int:
    """Return one decoded header field or reject an incomplete dissection."""
    if value is None:
        raise ValueError(f"IPv4/TCP {field_name} is unavailable")
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"IPv4/TCP {field_name} is invalid: {value!r}") from exc


def _validate_unfragmented_ipv4_tcp(ip: Any) -> None:
    """Reject IP states that cannot be handed to TCP reassembly safely."""
    version = _required_header_integer(getattr(ip, "version", None), "version")
    if version != 4:
        raise ValueError(f"expected IPv4 version 4, got {version}")

    fragment_offset = _required_header_integer(
        getattr(ip, "frag", None),
        "fragment offset",
    )
    flags = _required_header_integer(getattr(ip, "flags", None), "flags")
    if fragment_offset != 0 or flags & 0x01:
        raise ValueError(
            "fragmented IPv4/TCP packets are unsupported; "
            "TCP reassembly requires a complete IP datagram"
        )


def _captured_ipv4_length(ip: Any) -> int:
    """Return captured bytes without reserializing ordinary Scapy packets."""
    original = getattr(ip, "original", None)
    if isinstance(original, (bytes, bytearray, memoryview)) and original:
        return len(original)
    return len(bytes(ip))


def _extract_ipv4_tcp_payload(ip: Any, tcp: Any) -> bytes:
    """Return only application bytes declared by complete IPv4/TCP headers.

    Scapy exposes link-layer padding through ``tcp.payload`` even though those
    bytes lie beyond the IPv4 total length. The wire header lengths are the
    authority at this boundary so padding can never advance TCP sequence state.
    """
    total_length = _required_header_integer(
        getattr(ip, "len", None),
        "total length",
    )
    ip_header_words = _required_header_integer(
        getattr(ip, "ihl", None),
        "header length",
    )
    tcp_header_words = _required_header_integer(
        getattr(tcp, "dataofs", None),
        "TCP header length",
    )

    if not 5 <= ip_header_words <= 15:
        raise ValueError(
            f"invalid IPv4 header length: {ip_header_words} 32-bit words"
        )
    if not 5 <= tcp_header_words <= 15:
        raise ValueError(
            f"invalid TCP header length: {tcp_header_words} 32-bit words"
        )
    if not 0 <= total_length <= 0xFFFF:
        raise ValueError(f"invalid IPv4 total length: {total_length}")

    captured_length = _captured_ipv4_length(ip)
    if captured_length < total_length:
        raise ValueError(
            "truncated IPv4 packet: "
            f"header declares {total_length} bytes, capture has {captured_length}"
        )

    header_length = (ip_header_words + tcp_header_words) * 4
    if total_length < header_length:
        raise ValueError(
            "invalid IPv4/TCP header lengths: "
            f"total length {total_length} is smaller than {header_length}"
        )

    declared_length = total_length - header_length
    available = bytes(getattr(tcp, "payload", b""))
    if len(available) < declared_length:
        raise ValueError(
            "truncated IPv4/TCP payload: "
            f"header declares {declared_length} bytes, capture has {len(available)}"
        )
    return available[:declared_length]


def _consumer_server_ports(engine: SegmentConsumer) -> Optional[frozenset[int]]:
    """Read the validated port set exposed by each built-in consumer."""
    ports = getattr(engine, "server_ports", None)
    if ports is None:
        # Solare's internal collector predates the shared ``server_ports`` name.
        ports = getattr(engine, "ports", None)
    if ports is None:
        return None
    return frozenset(ports)


def make_packet_handler(engine: SegmentConsumer):
    IP, TCP, _, _, _ = import_scapy()
    server_ports = _consumer_server_ports(engine)

    def handle(packet) -> None:
        if IP not in packet:
            return

        ip = packet[IP]
        protocol = _required_header_integer(getattr(ip, "proto", None), "protocol")
        if protocol != 6:
            return

        if TCP not in packet:
            # Non-initial fragments and severely truncated headers have no
            # source port, so they cannot be attributed to a selected flow.
            return

        tcp = packet[TCP]
        source_port = int(tcp.sport)
        if server_ports is not None and source_port not in server_ports:
            return

        _validate_unfragmented_ipv4_tcp(ip)
        payload = _extract_ipv4_tcp_payload(ip, tcp)
        flags = int(tcp.flags)

        engine.process_tcp_segment(
            source_ip=str(ip.src),
            source_port=source_port,
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
    except (OSError, ValueError, Scapy_Exception) as exc:
        if source is not None:
            try:
                source.close()
            except BaseException:
                pass
        raise ValueError(f"Could not read capture {path}: {exc}") from exc

    active_error = False
    close_error: BaseException | None = None
    try:
        while True:
            try:
                packet = next(packets)
            except StopIteration:
                break
            except (OSError, ValueError, Scapy_Exception) as exc:
                raise ValueError(f"Could not read capture {path}: {exc}") from exc
            # Consumer/decoder failures are deliberately outside the reader
            # error wrapper so callers receive the original exception object.
            handler(packet)
            yield None
    except BaseException:
        active_error = True
        raise
    finally:
        if packets is not None:
            try:
                packets.close()
            except BaseException as exc:
                close_error = exc
        if source is not None:
            try:
                source.close()
            except BaseException as exc:
                if close_error is None:
                    close_error = exc
        if close_error is not None and not active_error:
            raise ValueError(
                f"Could not close capture {path}: {close_error}"
            ) from close_error

    engine.finish()


def replay_pcap_file(path: Path, engine: SegmentConsumer) -> None:
    """Process an entire capture file eagerly (calibration convenience)."""
    for _ in iter_pcap_file(path, engine):
        pass
