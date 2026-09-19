"""Bounded cold discovery, separate from selected-layout balance decoding.

No remembered opcode, message size, field offset, or profile participates in
identity. A unique capped decreasing uint32LE column remains an inference,
not proof that an unrelated resource cannot share those characteristics.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn

from .._protocol import BDOFrame, FlowKey
from ..events import Flow
from ._validation import validate_expected_maximum_points
from .models import (
    AgrisBalance,
    AgrisDetectionError,
    AgrisDiscoveryOptions,
    AgrisDiscoveryState,
    AgrisLayout,
    AgrisStatus,
)


@dataclass
class _Column:
    last: int
    distinct: int = 1


@dataclass
class _Family:
    caps: set[int]
    columns: dict[int, _Column]
    observed_at: float


type _FamilyKey = tuple[FlowKey, int, int, int]
type _CandidateKey = tuple[_FamilyKey, int, int]


def _public_flow(flow: FlowKey) -> Flow:
    return Flow(flow.source_ip, flow.source_port, flow.destination_ip, flow.destination_port)


class AgrisTracker:
    """Single-owner tracker; no raw frame history or consumption arithmetic.

    Before selection, a family's surviving columns must be nonincreasing and
    in range from its first observation. Contradicted hypotheses never restart
    midway through that family. After selection, direct decoding permits equal
    and increasing balances while discovery still checks competing hypotheses.
    """

    def __init__(
        self,
        *,
        expected_maximum_points: int,
        options: AgrisDiscoveryOptions | None = None,
        on_balance: Callable[[AgrisBalance], None] | None = None,
    ) -> None:
        self.expected_maximum_points = validate_expected_maximum_points(expected_maximum_points)
        if options is not None and not isinstance(options, AgrisDiscoveryOptions):
            raise TypeError("options must be AgrisDiscoveryOptions or None")
        if on_balance is not None and not callable(on_balance):
            raise TypeError("on_balance must be callable or None")
        self.options = options if options is not None else AgrisDiscoveryOptions()
        self._on_balance = on_balance
        self._families: dict[_FamilyKey, _Family] = {}
        self._column_count = 0
        self._observed_frames = 0
        self._clock = 0.0
        self._selected: _CandidateKey | None = None
        self._unique: _CandidateKey | None = None
        self._unique_since = 0.0
        self._candidates: tuple[_CandidateKey, ...] = ()
        self._candidates_dirty = False
        self._invalid_reason: str | None = None
        self._latest_balance: AgrisBalance | None = None
        self._selected_version = 0
        self._published_version = -1
        self._tracking = False

    @property
    def clock(self) -> float:
        """Latest settling clock, distinct from a balance's packet timestamp."""

        return self._clock

    def invalidate(self, reason: str) -> NoReturn:
        """Latch the first integrity failure and withdraw current authority."""

        if self._invalid_reason is None:
            self._invalid_reason = reason
        self._tracking = False
        raise AgrisDetectionError(self._invalid_reason)

    def observe(self, frame: BDOFrame) -> None:
        if self._invalid_reason is not None:
            raise AgrisDetectionError(self._invalid_reason)
        if not math.isfinite(frame.context.timestamp):
            self.invalidate("A frame has a non-finite observation timestamp.")
        self._observed_frames += 1
        self._clock = max(self._clock, frame.context.timestamp)
        message = frame.message
        if self._selected is not None:
            chosen = self._selected[0]
            if frame.context.flow == chosen[0] and frame.context.flow_generation != chosen[1]:
                self.invalidate("Selected connection epoch changed; restart discovery.")
        if len(message) < 5:
            self.refresh()
            return
        key = (frame.context.flow, frame.context.flow_generation, frame.opcode, len(message))
        if self._selected is not None:
            chosen = self._selected[0]
            if key[:3] == chosen[:3]:
                if key != chosen or frame.flag != 0 or frame.length != len(message):
                    self.invalidate("Selected message shape changed; restart discovery.")
                self._decode_selected(frame)
        if frame.flag != 0 or frame.length != len(message):
            self.refresh()
            return
        if key not in self._families:
            self._add_family(key, message, frame.context.timestamp)
        else:
            self._update_family(key, message, frame.context.timestamp)
        self.refresh()

    def _add_family(self, key: _FamilyKey, message: bytes, observed_at: float) -> None:
        if len(self._families) >= self.options.max_families:
            self.invalidate("Discovery family limit reached; no hypotheses were silently evicted.")
        cap_bytes = self.expected_maximum_points.to_bytes(4, "little")
        caps: set[int] = set()
        offset = message.find(cap_bytes, 5)
        while offset != -1:
            caps.add(offset)
            offset = message.find(cap_bytes, offset + 1)
        columns: dict[int, _Column] = {}
        if caps:
            for offset in range(5, len(message) - 3):
                value = int.from_bytes(message[offset : offset + 4], "little")
                if value <= self.expected_maximum_points:
                    if self._column_count + len(columns) >= self.options.max_columns:
                        self.invalidate("Discovery column limit reached; no hypotheses were silently evicted.")
                    columns[offset] = _Column(value)
        self._column_count += len(columns)
        self._families[key] = _Family(caps, columns, observed_at)
        self._candidates_dirty = True

    def _update_family(self, key: _FamilyKey, message: bytes, observed_at: float) -> None:
        family = self._families[key]
        family.observed_at = observed_at
        family.caps.intersection_update(
            offset for offset in tuple(family.caps)
            if int.from_bytes(message[offset : offset + 4], "little") == self.expected_maximum_points
        )
        for offset, column in tuple(family.columns.items()):
            value = int.from_bytes(message[offset : offset + 4], "little")
            selected_column = self._selected is not None and self._selected[:2] == (key, offset)
            if not family.caps or value > self.expected_maximum_points or (value > column.last and not selected_column):
                del family.columns[offset]
                self._column_count -= 1
            else:
                # Only comparison counts support inference: never derive spending.
                if value < column.last and column.distinct < self.options.minimum_updates:
                    column.distinct += 1
                column.last = value
        self._candidates_dirty = True

    def _decode_selected(self, frame: BDOFrame) -> None:
        assert self._selected is not None
        _, offset, cap_offset = self._selected
        remaining = int.from_bytes(frame.message[offset : offset + 4], "little")
        maximum = int.from_bytes(frame.message[cap_offset : cap_offset + 4], "little")
        if maximum != self.expected_maximum_points or remaining > maximum:
            self.invalidate("Selected balance or cap is outside the validated layout constraints.")
        self._latest_balance = AgrisBalance(
            remaining_points=remaining,
            maximum_points=maximum,
            observed_at=frame.context.timestamp,
            flow=_public_flow(frame.context.flow),
            connection_epoch=frame.context.flow_generation,
        )
        self._selected_version += 1

    def _find_candidates(self) -> None:
        if not self._candidates_dirty:
            return
        candidates: list[_CandidateKey] = []
        for key, family in self._families.items():
            for offset, column in family.columns.items():
                if column.distinct < self.options.minimum_updates:
                    continue
                for cap_offset in sorted(family.caps):
                    if abs(cap_offset - offset) < 4:
                        continue
                    if len(candidates) >= self.options.max_candidates:
                        self.invalidate("Discovery candidate limit reached; uniqueness is unresolved.")
                    candidates.append((key, offset, cap_offset))
        self._candidates = tuple(candidates)
        self._candidates_dirty = False

    def refresh(self, now: float | None = None) -> AgrisStatus:
        """Advance observation time and publish only the newest authorized balance.

        Live owners must not advance time while accepted packets remain queued.
        Offline owners use capture timestamps, never today's wall clock.
        """

        if now is not None:
            if isinstance(now, bool) or not isinstance(now, (int, float)):
                raise TypeError("now must be a finite number or None")
            if not math.isfinite(now):
                raise ValueError("now must be finite")
            self._clock = max(self._clock, now)
        if self._invalid_reason is not None:
            return self.snapshot()
        self._find_candidates()
        unique = self._candidates[0] if len(self._candidates) == 1 else None
        if unique != self._unique:
            self._unique = unique
            self._unique_since = self._clock
        was_tracking = self._tracking
        self._tracking = False
        if unique is not None and self._clock - self._unique_since >= self.options.settle_seconds:
            if self._selected is not None and unique != self._selected:
                self.invalidate("A different hypothesis replaced the selected layout; restart discovery.")
            if self._selected is None:
                self._selected = unique
                key, offset, _ = unique
                family = self._families[key]
                self._latest_balance = AgrisBalance(
                    remaining_points=family.columns[offset].last,
                    maximum_points=self.expected_maximum_points,
                    observed_at=family.observed_at,
                    flow=_public_flow(key[0]),
                    connection_epoch=key[1],
                )
            self._tracking = True
        if self._tracking and (not was_tracking or self._published_version != self._selected_version):
            assert self._latest_balance is not None
            self._published_version = self._selected_version
            if self._on_balance is not None:
                self._on_balance(self._latest_balance)
        return self.snapshot()

    def snapshot(self) -> AgrisStatus:
        """Read immutable state without advancing time or emitting events."""

        state: AgrisDiscoveryState
        if self._invalid_reason is not None:
            state = "invalid"
        elif len(self._candidates) > 1:
            state = "ambiguous"
        elif not self._candidates:
            state = "searching"
        elif self._tracking:
            state = "tracking"
        else:
            state = "settling"
        return AgrisStatus(
            status=state,
            expected_maximum_points=self.expected_maximum_points,
            balance=self._latest_balance if state == "tracking" else None,
            candidates=tuple(
                AgrisLayout(key[2], key[3], offset, cap_offset, _public_flow(key[0]), key[1])
                for key, offset, cap_offset in self._candidates
            ),
            observed_frames=self._observed_frames,
            reason=self._invalid_reason,
        )

    def close_flow(self, flow: FlowKey) -> None:
        if self._selected is not None and self._selected[0][0] == flow:
            self.invalidate("Selected connection ended; restart discovery for a new connection.")
        for key in tuple(self._families):
            if key[0] == flow:
                self._column_count -= len(self._families.pop(key).columns)
                self._candidates_dirty = True
        self.refresh()

    def gap_reset(self, flow: FlowKey, generation: int, resume_sequence: int) -> None:
        # Reassembly gap recovery need not increment the connection generation.
        self.invalidate("TCP gap detected; restart discovery with an intact capture.")
