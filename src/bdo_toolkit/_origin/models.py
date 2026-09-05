"""Private deposit-origin models implementation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from .._protocol import FlowKey
from ..events import BDOEvent
from ..origin_learning import CompanionObservation


ORIGIN_WORKER = "worker"


ORIGIN_MANUAL = "manual"


ORIGIN_UNKNOWN = "unknown"


SOURCE_WORKER_PRODUCTION = "Worker Production"


SOURCE_PLAYER_INVENTORY = "Player Inventory"


type _CompanionDiscoveryKey = tuple[bytes, int, int, bytes, bytes]


@dataclass(frozen=True)
class DecrementSpec:
    """One source-stack-decrement shape to test candidates against."""

    opcode: int
    min_message_length: int
    quantity_offset: int
    source_instance_offset: Optional[int] = None
    repeat_stride: Optional[int] = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.opcode, bool)
            or not isinstance(self.opcode, int)
            or not 0 <= self.opcode <= 0xFFFF
        ):
            raise ValueError("decrement opcode must be a uint16")
        if (
            isinstance(self.min_message_length, bool)
            or not isinstance(self.min_message_length, int)
            or self.min_message_length < 5
        ):
            raise ValueError("decrement minimum message length must be at least 5")
        if (
            isinstance(self.quantity_offset, bool)
            or not isinstance(self.quantity_offset, int)
            or not 0 <= self.quantity_offset <= self.min_message_length - 4
        ):
            raise ValueError("decrement quantity offset must fit its minimum shape")
        if self.source_instance_offset is not None and (
            isinstance(self.source_instance_offset, bool)
            or not isinstance(self.source_instance_offset, int)
            or self.source_instance_offset < 0
            or self.source_instance_offset + 8 > self.min_message_length
        ):
            raise ValueError(
                "decrement source instance offset must fit its minimum shape"
            )
        if self.repeat_stride is not None and (
            isinstance(self.repeat_stride, bool)
            or not isinstance(self.repeat_stride, int)
            or self.repeat_stride <= 0
        ):
            raise ValueError("decrement repeat stride must be positive or None")
        if self.repeat_stride is not None:
            prefix_length = self.min_message_length - self.repeat_stride
            if (
                prefix_length < 5
                or self.quantity_offset < prefix_length
                or (
                    self.source_instance_offset is not None
                    and self.source_instance_offset < prefix_length
                )
            ):
                raise ValueError(
                    "decrement repeat stride must place repeated fields "
                    "after the frame prefix"
                )


@dataclass(frozen=True)
class _ManualDecrementMatch:
    """Strength and anchored geometry of one manual-deposit signal."""

    opcode: int
    message_length: int
    quantity_offset: int
    source_instance_offset: Optional[int]
    match_kind: str
    confidence: str
    instance_matches_destination: Optional[bool]

    def to_dict(self) -> dict[str, object]:
        output: dict[str, object] = {
            "opcode": f"0x{self.opcode:04X}",
            "message_length": self.message_length,
            "quantity_offset": self.quantity_offset,
            "match_kind": self.match_kind,
            "confidence": self.confidence,
        }
        if self.source_instance_offset is not None:
            output["source_instance_offset"] = self.source_instance_offset
        if self.instance_matches_destination is not None:
            output["instance_matches_destination"] = (
                self.instance_matches_destination
            )
        return output


type _ManualFlowKey = tuple[FlowKey, int]


type _ManualOperationKey = tuple[
    FlowKey,
    int,
    Optional[int],
    Optional[int],
    Optional[int],
    float,
]


@dataclass(eq=False)
class _ManualDecrementCandidate:
    """One physical calibrated decrement frame awaiting unique ownership."""

    flow: FlowKey
    flow_generation: int
    stream_start: int
    stream_end: int
    timestamp: float
    opcode: int
    message: bytes
    specs: tuple[DecrementSpec, ...]
    successor_starts: list[int] = field(default_factory=list)
    reserved_by: Optional[_ManualOperationKey] = None

    @property
    def message_length(self) -> int:
        return len(self.message)


@dataclass
class _PendingDeposit:
    event: BDOEvent
    flow: FlowKey
    stream_sequence: Optional[int]
    timestamp: float
    matching_decrement: bool
    events: tuple[BDOEvent, ...] = ()
    matching_decrement_record_indexes: tuple[int, ...] = ()
    manual_decrement_matches: tuple[
        tuple[int, _ManualDecrementMatch], ...
    ] = ()
    frames_after: int = 0
    end_sequence: Optional[int] = None
    companion_observation: Optional[CompanionObservation] = None
    delta_message: Optional[bytes] = None
    delta_prefix_end: Optional[int] = None
    candidate_observations: dict[
        tuple[int, int, int, int, int], CompanionObservation
    ] = field(default_factory=dict)
    awaiting_storage_boundaries: frozenset[int] = frozenset()
    finalized: bool = False


@dataclass(frozen=True)
class _StreamSpan:
    start: int
    data: bytes

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass(frozen=True)
class _CompanionScan:
    observations: tuple[CompanionObservation, ...]
    complete: bool
    immediate_family_keys: frozenset[tuple[int, int, int, int, int]] = frozenset()
    awaiting_storage_boundaries: frozenset[int] = frozenset()


@dataclass
class _StagedStorageBatch:
    """Records from one storage wrapper awaiting one atomic decision."""

    expected_count: int
    entries: dict[int, tuple[BDOEvent, Optional[bytes]]] = field(
        default_factory=dict
    )
    invalid: bool = False
