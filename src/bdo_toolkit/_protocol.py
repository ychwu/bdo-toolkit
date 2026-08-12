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

CHARACTER_LOAD_CONTEXT = b"\x00" * 4
# Legacy storage-delta signatures that calibration has observed at varying
# pre-record offsets. The complete location registry below must not be used as
# a free-form signature list: small town IDs can coincide with ordinary uint32
# fields elsewhere in a message.
STORAGE_DELTA_CONTEXTS = tuple(
    storage_id.to_bytes(4, "little") for storage_id in (0x0005, 0x0020, 0x058C)
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
    STORAGE_DELTA_CONTEXTS[0]: "Velia",
    STORAGE_DELTA_CONTEXTS[1]: "Heidel",
    STORAGE_DELTA_CONTEXTS[2]: "Yukjo Street",
    bytes.fromhex("43ce1321"): "Central Market",
    bytes.fromhex("89fa09af"): "Black Spirit Safe",
    bytes.fromhex("35bd5d70"): "Challenges",
    bytes.fromhex("ef6b9b51"): "In-Game Mail",
    bytes.fromhex("8f92e3de"): "Box/Bundle",
    bytes.fromhex("8b7c3a13"): "NPC Exchange",
    bytes.fromhex("721f296d"): "NPC Shop",
    bytes.fromhex("56687f25"): "Choose Your Rewards Box",
    bytes.fromhex("52e89da8"): "NPC Sell",
    bytes.fromhex("60260000"): "Event Adventures",
    bytes.fromhex("3e010000"): "Remote Inventory",
}


@dataclass(frozen=True)
class StorageLocation:
    """Best-known name for a numeric storage destination key.

    ``confidence`` distinguishes names directly proven by a unique occupied
    record count or controlled storage action from names inferred within
    equal-count groups, and names of empty destinations that are still
    provisional. The key itself is the durable protocol value; applications
    should not treat a provisional name as an identity.
    """

    name: str
    confidence: str


# Numeric little-endian town/storage keys observed in the 2026-07-17 initial
# game-load storage snapshot. Some older profiles placed the field at another
# offset, but captures confirm that it was still the destination key.
STORAGE_LOCATIONS: dict[int, StorageLocation] = {
    # Direct observations from unique occupied-record counts or controlled
    # storage actions.
    0x0005: StorageLocation("Velia", "observed"),
    0x0020: StorageLocation("Heidel", "observed"),
    0x0034: StorageLocation("Glish", "observed"),
    0x004D: StorageLocation("Calpheon City", "observed"),
    0x0058: StorageLocation("Olvia", "observed"),
    0x0078: StorageLocation("Port Epheria", "observed"),
    0x00CA: StorageLocation("Altinova", "observed"),
    0x00DA: StorageLocation("Asparkan", "observed"),
    0x00DD: StorageLocation("Tarif", "observed"),
    0x025D: StorageLocation("Sand Grain Bazaar", "observed"),
    0x02B5: StorageLocation("Arehaza", "observed"),
    0x02C2: StorageLocation("Old Wisdom Tree", "observed"),
    0x0369: StorageLocation("Duvencrune", "observed"),
    0x03BB: StorageLocation("O'draxxia", "observed"),
    0x03E8: StorageLocation("Oquilla's Eye", "observed"),
    0x0464: StorageLocation("Eilton", "observed"),
    0x04C3: StorageLocation("Nampo's Moodle Village", "observed"),
    0x04DE: StorageLocation("Nopsae's Byeot County", "observed"),
    0x055F: StorageLocation("Muzgar", "observed"),
    0x0566: StorageLocation("Velandir", "observed"),
    0x058C: StorageLocation("Yukjo Street", "observed"),
    # Confirmed by controlled manual deposits on 2026-07-17. These wrappers
    # carried the expected numeric destination key and normalized town name.
    0x0590: StorageLocation("Godu Village", "observed"),
    0x05A4: StorageLocation("Bukpo", "observed"),
    # The capture fixes each key to an equal-count group; the exact name in
    # each group follows the established region-key ordering and is inferred.
    0x006B: StorageLocation("Keplan", "inferred"),
    0x007E: StorageLocation("Trent", "inferred"),
    0x00B6: StorageLocation("Iliya Island", "inferred"),
    0x00E5: StorageLocation("Shakatu", "inferred"),
    0x0259: StorageLocation("Valencia City", "inferred"),
    0x026B: StorageLocation("Ancado Inner Harbor", "inferred"),
    0x02DF: StorageLocation("Grana", "inferred"),
    0x04BA: StorageLocation("Dalbeol Village", "inferred"),
    # Empty messages carry no item content with which to prove the name.
    0x02B6: StorageLocation("Muiquun", "probable"),
    0x0611: StorageLocation("Hakinza Sanctuary", "probable"),
}


def storage_location(storage_id: Optional[int]) -> Optional[StorageLocation]:
    """Return the best-known location metadata for a storage key."""

    if storage_id is None:
        return None
    return STORAGE_LOCATIONS.get(storage_id)


def storage_destination_candidates(
    message: bytes,
    *,
    before_offset: int,
) -> tuple[tuple[int, int], ...]:
    """Return registered four-byte destination keys in a wrapper prefix.

    The destination field has moved to unrelated absolute and item-relative
    positions across every observed storage generation.  Its stable wire
    invariant is the little-endian numeric key itself, so callers discover
    candidates across the validated prefix and resolve ambiguity with either
    calibration evidence or cross-frame field consistency.

    This helper deliberately does not choose a candidate.  A true ``0x05xx``
    destination can overlap a false Velia key one byte later, so selecting the
    first, last, or closest match would silently assign the wrong town.
    """

    if before_offset <= 5:
        return ()
    search_end = min(before_offset, len(message))
    return tuple(
        (offset, storage_id)
        for offset in range(5, max(5, search_end - 3))
        if (
            storage_id := int.from_bytes(
                message[offset : offset + 4],
                "little",
            )
        )
        in STORAGE_LOCATIONS
    )


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
    record_count_offset: Optional[int] = None
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
        if self.record_count_offset is not None and self.record_count_offset < 0:
            raise ValueError(f"{self.label} record_count_offset must be >= 0")
        if self.label == "INVENTORY_TO_STORAGE":
            if (
                self.source_context_offset is not None
                and self.source_context_offset + self.source_context_length
                > self.item_offset
            ):
                raise ValueError(
                    f"{self.label} source_context_offset must end before item_offset"
                )
            if (
                self.record_count_offset is not None
                and self.record_count_offset + 2 > self.item_offset
            ):
                raise ValueError(
                    f"{self.label} record_count_offset must end before item_offset"
                )
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
    # A FlowKey identifies a TCP four-tuple, not one connection lifetime.
    # FlowManager assigns a new generation whenever that tuple is opened
    # again so consumers that retain frames cannot merge independent streams.
    flow_generation: int = 0


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
    # Storage-family metadata. Normalization can derive ``storage_id`` from the
    # calibration-selected four-byte destination field when a producer leaves
    # the redundant normalized value unset.
    storage_id: Optional[int] = None
    storage_operation: Optional[str] = None


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
