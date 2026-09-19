"""Immutable observations and diagnostics for provisional Agris discovery.

These models describe observed balances, not a starting balance or spending.
The caller-supplied cap constrains discovery; it does not prove identity.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

from ..events import Flow
from ._validation import validate_expected_maximum_points


class AgrisDetectionError(RuntimeError):
    """Discovery or capture integrity no longer permits balance authority."""


@dataclass(frozen=True)
class AgrisDiscoveryOptions:
    """Bounded, session-local discovery policy.

    ``minimum_updates`` counts distinct decreasing balances, not repeated
    packets. The unique candidate must survive ``settle_seconds`` of observed
    time. Resource exhaustion fails closed rather than discarding competitors.
    """

    minimum_updates: int = 5
    settle_seconds: float = 3.0
    max_families: int = 2048
    max_columns: int = 65536
    max_candidates: int = 4096

    def __post_init__(self) -> None:
        for name, minimum in (
            ("minimum_updates", 3),
            ("max_families", 1),
            ("max_columns", 1),
            ("max_candidates", 1),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value < minimum:
                raise ValueError(f"{name} must be >= {minimum}")
        if isinstance(self.settle_seconds, bool) or not isinstance(
            self.settle_seconds, (int, float)
        ):
            raise TypeError("settle_seconds must be a number")
        if not math.isfinite(self.settle_seconds) or self.settle_seconds < 0:
            raise ValueError("settle_seconds must be finite and nonnegative")


@dataclass(frozen=True)
class AgrisBalance:
    """Latest balance read from an inferred layout, at its packet timestamp."""

    remaining_points: int
    maximum_points: int
    observed_at: float
    flow: Flow
    connection_epoch: int
    confidence: Literal["inferred"] = "inferred"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "event_type": "agris_balance",
            "remaining_points": self.remaining_points,
            "maximum_points": self.maximum_points,
            "observed_at": self.observed_at,
            "flow": self.flow.to_dict(),
            "connection_epoch": self.connection_epoch,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class AgrisLayout:
    """Session-local layout evidence, never persisted as an opcode profile."""

    opcode: int
    message_length: int
    remaining_offset: int
    maximum_offset: int
    flow: Flow
    connection_epoch: int

    def to_dict(self) -> dict[str, object]:
        return {
            "opcode": self.opcode,
            "message_length": self.message_length,
            "remaining_offset": self.remaining_offset,
            "maximum_offset": self.maximum_offset,
            "flow": self.flow.to_dict(),
            "connection_epoch": self.connection_epoch,
        }


AgrisDiscoveryState = Literal["searching", "settling", "tracking", "ambiguous", "invalid"]


@dataclass(frozen=True)
class AgrisStatus:
    """Current authority and bounded discovery evidence.

    ``balance`` is unavailable outside ``tracking``. Even while tracking it is
    an observation, not a guarantee that the game balance has not since changed.
    """

    status: AgrisDiscoveryState
    expected_maximum_points: int
    balance: AgrisBalance | None
    candidates: tuple[AgrisLayout, ...]
    observed_frames: int
    reason: str | None = None

    def __post_init__(self) -> None:
        validate_expected_maximum_points(self.expected_maximum_points)
        # Preserve immutability even for callers supplying a list at runtime.
        object.__setattr__(self, "candidates", tuple(self.candidates))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": self.status,
            "expected_maximum_points": self.expected_maximum_points,
            "balance": self.balance.to_dict() if self.balance is not None else None,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "observed_frames": self.observed_frames,
            "reason": self.reason,
        }
