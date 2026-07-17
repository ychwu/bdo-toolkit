"""Core BDO wire-protocol model: constants, event specs, and decoded records.

The BDO application-message header observed in captures is:

    uint16_le message_length
    uint8     flags/unknown
    uint16_le opcode

Offsets and labels are provisional observations and may change after a game
patch. Everything here is read-only protocol knowledge; no packets are ever
sent or modified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

DEFAULT_SERVER_PORTS = (8884, 8885, 8889)
# The frame header carries a uint16 length.  The older 4096-byte ceiling
# silently rejected otherwise-valid storage batches at 18 records
# (35 + 18 * 226 = 4103 bytes), so accept the full wire range and rely on the
# structural guards in the scanners to reject false candidates.
MAX_TARGET_MESSAGE_LENGTH = 0xFFFF
BASE_ITEM_ID_MASK = 0x00FFFFFF
MAX_ENHANCEMENT_LEVEL = 20
MAX_PLAUSIBLE_ITEM_ID = (MAX_ENHANCEMENT_LEVEL << 24) | BASE_ITEM_ID_MASK
MAX_PENDING_SEGMENTS = 128
GAP_RESET_SECONDS = 1.5
DEDUP_HISTORY_LIMIT = 4096
TCP_SEQUENCE_MODULUS = 1 << 32
TCP_SEQUENCE_HALF_RANGE = TCP_SEQUENCE_MODULUS >> 1
LOOT_PREVIEW_SENTINEL_INSTANCE = b"\xff" * 8

CURRENT_INVENTORY_TRANSFER_RECORD_BASE_LENGTH = 27
CURRENT_STORAGE_DELTA_RECORD_STRIDE = 226
CHARACTER_LOAD_CONTEXT = b"\x00" * 4
STORAGE_DELTA_CONTEXTS = (
    bytes.fromhex("05000000"),
    bytes.fromhex("20000000"),
    # Royal Workshop production deposits (observed 2026-07-08, item 821108,
    # 2-record frame; n=1, no pcap yet — produces intermittently). Registered
    # here so these frames get the intrinsic into_storage direction signal and
    # are never mistaken for a receipt context label. Worker attribution is
    # deposit_origin's job, never the context byte (see the 20000000 history).
    bytes.fromhex("8c050000"),
)

ENHANCEMENT_LABELS: dict[int, str] = {
    1: "PRI",
    2: "DUO",
    3: "TRI",
    4: "TET",
    5: "PEN",
    6: "HEX",
    7: "SEP",
    8: "OCT",
    9: "NOV",
    10: "DEC",
    16: "PRI",
    17: "DUO",
    18: "TRI",
    19: "TET",
    20: "PEN",
}

SOURCE_CONTEXT_LABELS: dict[bytes, str] = {
    CHARACTER_LOAD_CONTEXT: "Character Load",
    bytes.fromhex("0471ee0e"): "Gathering",
    bytes.fromhex("85fa5745"): "Mob Drop",
    bytes.fromhex("d0f205a3"): "Storage",
    STORAGE_DELTA_CONTEXTS[0]: "Storage",
    # 0x20 is batch-style storage delta: seen on worker deposits (any record
    # count, including single) AND manual multi-record deposits. It is NOT
    # worker-specific; worker isolation needs correlation (see wiki).
    STORAGE_DELTA_CONTEXTS[1]: "Batch Storage Deposit",
    STORAGE_DELTA_CONTEXTS[2]: "Royal Workshop",
    bytes.fromhex("43ce1321"): "Central Market",
    bytes.fromhex("89fa09af"): "Black Spirit Safe",
    bytes.fromhex("35bd5d70"): "Challenges",
    bytes.fromhex("ef6b9b51"): "In-Game Mail",
    bytes.fromhex("8f92e3de"): "Box/Bundle",
    bytes.fromhex("8b7c3a13"): "NPC Exchange",
    bytes.fromhex("721f296d"): "NPC Shop",
    bytes.fromhex("56687f25"): "Choose Your Rewards Box",
    bytes.fromhex("52e89da8"): "NPC Sell",
}


@dataclass(frozen=True)
class EventSpec:
    label: str
    opcode: int
    item_offset: int
    quantity_offset: int
    min_message_length: int
    inventory_slot_offset: Optional[int] = None
    source_context_offset: Optional[int] = None
    source_context_length: int = 4
    item_instance_offset: Optional[int] = None
    storage_instance_offset: Optional[int] = None
    repeat_stride: Optional[int] = None
    single_record_message_length: Optional[int] = None
    default_context: Optional[str] = None

    @property
    def signature(self) -> bytes:
        # Header bytes at message offsets 2..4: unknown/flags byte + opcode LE.
        return b"\x00" + self.opcode.to_bytes(2, "little")

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("event spec label must not be empty")
        if (
            isinstance(self.opcode, bool)
            or not isinstance(self.opcode, int)
            or not 0 <= self.opcode <= 0xFFFF
        ):
            raise ValueError(f"{self.label} opcode must be a uint16")
        if self.item_offset < 0:
            raise ValueError(f"{self.label} item_offset must be >= 0")
        if self.quantity_offset < 0:
            raise ValueError(f"{self.label} quantity_offset must be >= 0")
        if not 5 <= self.min_message_length <= MAX_TARGET_MESSAGE_LENGTH:
            raise ValueError(
                f"{self.label} min_message_length must be between 5 and "
                f"{MAX_TARGET_MESSAGE_LENGTH}"
            )
        if self.inventory_slot_offset is not None and self.inventory_slot_offset < 0:
            raise ValueError(f"{self.label} inventory_slot_offset must be >= 0")
        if self.source_context_offset is not None:
            if self.source_context_offset < 0:
                raise ValueError(f"{self.label} source_context_offset must be >= 0")
            if self.source_context_length <= 0:
                raise ValueError(f"{self.label} source_context_length must be > 0")
        if self.storage_instance_offset is not None and self.storage_instance_offset < 0:
            raise ValueError(f"{self.label} storage_instance_offset must be >= 0")
        if self.item_instance_offset is not None and self.item_instance_offset < 0:
            raise ValueError(f"{self.label} item_instance_offset must be >= 0")
        if self.repeat_stride is not None and self.repeat_stride <= 0:
            raise ValueError(f"{self.label} repeat_stride must be > 0")
        if self.single_record_message_length is not None:
            if (
                isinstance(self.single_record_message_length, bool)
                or not isinstance(self.single_record_message_length, int)
            ):
                raise ValueError(
                    f"{self.label} single_record_message_length must be an integer"
                )
            if not (
                self.min_message_length
                <= self.single_record_message_length
                <= MAX_TARGET_MESSAGE_LENGTH
            ):
                raise ValueError(
                    f"{self.label} single_record_message_length must be between "
                    "min_message_length and 65535"
                )


@dataclass(frozen=True)
class FlowKey:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    def __str__(self) -> str:
        return (
            f"{self.source_ip}:{self.source_port} -> "
            f"{self.destination_ip}:{self.destination_port}"
        )


@dataclass(frozen=True)
class PacketContext:
    timestamp: float
    flow: FlowKey
    stream_start: Optional[int] = None


@dataclass(frozen=True)
class LootEvent:
    """One decoded item record, pre-normalization."""

    label: str
    opcode: int
    item_id: int
    quantity: int
    inventory_slot: Optional[int]
    source_context_candidate: Optional[bytes]
    item_instance: Optional[bytes]
    storage_instance: Optional[bytes]
    message_length: int
    default_context: Optional[str]
    context: PacketContext
    stream_sequence: Optional[int] = None
    record_offset: Optional[int] = None
    record_index: Optional[int] = None
    record_count: Optional[int] = None


EventCallback = Callable[[LootEvent, bytes], None]


@dataclass(frozen=True)
class BDOFrame:
    """One generic length-framed BDO message, used by calibration."""

    index: int
    message: bytes
    context: PacketContext
    stream_sequence: Optional[int]

    @property
    def length(self) -> int:
        return int.from_bytes(self.message[0:2], "little")

    @property
    def flag(self) -> int:
        return self.message[2]

    @property
    def opcode(self) -> int:
        return int.from_bytes(self.message[3:5], "little")

    @property
    def payload(self) -> bytes:
        return self.message[5:]


def split_item_id_enhancement(item_id: int) -> tuple[int, Optional[int], Optional[str]]:
    enhancement_level = item_id >> 24
    base_item_id = item_id & BASE_ITEM_ID_MASK
    if 1 <= enhancement_level <= MAX_ENHANCEMENT_LEVEL:
        return base_item_id, enhancement_level, ENHANCEMENT_LABELS.get(enhancement_level)
    return item_id, None, None


def source_label(
    candidate: Optional[bytes],
    default_context: Optional[str] = None,
) -> Optional[str]:
    """App-facing source label for a raw context candidate.

    Known contexts map to their label. The spec default applies only when the
    message carries no context bytes at all; an unrecognized candidate is
    preserved as ``UNKNOWN(0x...)`` so new contexts stay visible to apps
    instead of silently matching an existing source filter.
    """
    if candidate is None:
        return default_context
    label = SOURCE_CONTEXT_LABELS.get(candidate)
    if label is not None:
        return label
    return f"UNKNOWN(0x{candidate.hex()})"
