"""Validated configuration objects for live packet capture."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

from ._capture_backend import validate_server_ports
from ._protocol import DEFAULT_SERVER_PORTS


@dataclass(frozen=True)
class PacketCaptureOptions:
    """Packet-acquisition settings shared by live decoding and calibration."""

    interface: Optional[str] = None
    local_ip: Optional[str] = None
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS
    use_bpf: bool = True
    auto_local_ip: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "ports", validate_server_ports(self.ports))
        if not isinstance(self.use_bpf, bool):
            raise ValueError("use_bpf must be a boolean")
        if not isinstance(self.auto_local_ip, bool):
            raise ValueError("auto_local_ip must be a boolean")
        if self.local_ip is not None:
            try:
                normalized_ip = str(ipaddress.IPv4Address(self.local_ip))
            except ipaddress.AddressValueError as exc:
                raise ValueError(
                    f"local_ip must be an IPv4 address: {self.local_ip!r}"
                ) from exc
            object.__setattr__(self, "local_ip", normalized_ip)


@dataclass(frozen=True)
class LiveCaptureOptions(PacketCaptureOptions):
    """Packet capture plus bounded packet/event buffering for live APIs.

    Packets are handed off from the native capture callback to a decoder
    worker through ``packet_queue_size``.  Decoded events are then buffered
    for the application through ``event_queue_size``.  Keeping those two
    bounds separate prevents a slow application callback from blocking the
    native capture thread without making memory use unbounded.
    """

    event_queue_size: int = 1024
    packet_queue_size: int = 4096

    def __post_init__(self) -> None:
        super().__post_init__()
        if (
            isinstance(self.event_queue_size, bool)
            or not isinstance(self.event_queue_size, int)
        ):
            raise ValueError("event_queue_size must be an integer")
        if self.event_queue_size <= 0:
            raise ValueError("event_queue_size must be greater than zero")
        if (
            isinstance(self.packet_queue_size, bool)
            or not isinstance(self.packet_queue_size, int)
        ):
            raise ValueError("packet_queue_size must be an integer")
        if self.packet_queue_size <= 0:
            raise ValueError("packet_queue_size must be greater than zero")
