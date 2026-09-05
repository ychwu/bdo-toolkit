"""Private deposit-origin manual implementation."""

from __future__ import annotations

from collections import deque
from typing import Iterable, Optional
from .._protocol import BDOFrame, FlowKey
from ..events import BDOEvent
from .models import (
    DecrementSpec,
    _ManualDecrementCandidate,
    _ManualDecrementMatch,
    _ManualFlowKey,
    _ManualOperationKey,
)


class _ManualDecrementLedger:
    """Bounded manual evidence; callers serialize access with the tracker lock."""

    MANUAL_IMMEDIATE_SUCCESSORS = 2
    MAX_MANUAL_CANDIDATES_PER_FLOW = 128
    MAX_MANUAL_CANDIDATES_TOTAL = 4096
    MAX_MANUAL_CANDIDATE_BYTES_PER_FLOW = 2 * 1024 * 1024
    MAX_MANUAL_CANDIDATE_BYTES_TOTAL = 32 * 1024 * 1024

    def __init__(self, decrement_specs: Iterable[DecrementSpec], stale_seconds: float) -> None:
        self.STALE_SECONDS = stale_seconds
        self._decrement_specs: dict[int, list[DecrementSpec]] = {}
        for spec in decrement_specs:
            matches = self._decrement_specs.setdefault(spec.opcode, [])
            if spec not in matches:
                matches.append(spec)
        self._manual_candidates: dict[
            _ManualFlowKey,
            deque[_ManualDecrementCandidate],
        ] = {}
        self._manual_candidate_count = 0
        self._manual_candidate_bytes = 0
        self._manual_candidate_bytes_by_flow: dict[_ManualFlowKey, int] = {}
        self._manual_active_generations: dict[FlowKey, int] = {}
        self._manual_frame_frontiers: dict[_ManualFlowKey, int] = {}
        self._manual_reset_floors: dict[_ManualFlowKey, int] = {}
        self._manual_latest_timestamps: dict[_ManualFlowKey, float] = {}
        self._manual_suppressed_until: dict[_ManualFlowKey, float] = {}

    def _observe_manual_frame_locked(self, frame: BDOFrame) -> None:
        """Retain only calibrated decrement frames for manual correlation."""

        flow = frame.context.flow
        generation = frame.context.flow_generation
        if not self._activate_manual_generation_locked(flow, generation):
            return
        key = (flow, generation)
        now = frame.context.timestamp
        self._manual_latest_timestamps[key] = max(
            now,
            self._manual_latest_timestamps.get(key, now),
        )

        start = frame.stream_sequence
        if start is None:
            return
        end = start + len(frame.message)
        reset_floor = self._manual_reset_floors.get(key)
        if reset_floor is not None and start < reset_floor:
            return

        # Generic callbacks normally advance monotonically. A frame wholly or
        # partly behind this frontier came from standalone retransmission
        # scanning and must not resurrect an old physical decrement.
        frontier = self._manual_frame_frontiers.get(key)
        if frontier is not None and start < frontier:
            return

        candidates = self._manual_candidates.get(key, ())
        for candidate in candidates:
            if (
                candidate.stream_end <= start
                and len(candidate.successor_starts)
                < self.MANUAL_IMMEDIATE_SUCCESSORS
                and start not in candidate.successor_starts
            ):
                candidate.successor_starts.append(start)
        self._manual_frame_frontiers[key] = max(end, frontier or end)

        specs = tuple(
            spec
            for spec in self._decrement_specs.get(frame.opcode, ())
            if self._manual_spec_accepts_message(spec, frame.message)
        )
        if not specs:
            return

        self._prune_manual_candidates_locked(now)
        ledger = self._manual_candidates.setdefault(key, deque())
        for candidate in ledger:
            if (
                candidate.stream_start == start
                and candidate.stream_end == end
                and candidate.opcode == frame.opcode
            ):
                return

        if self._manual_key_is_suppressed_locked(key):
            self._suppress_manual_key_locked(key, now)
            return

        message_size = len(frame.message)
        flow_bytes = self._manual_candidate_bytes_by_flow.get(key, 0)
        if (
            len(ledger) >= self.MAX_MANUAL_CANDIDATES_PER_FLOW
            or self._manual_candidate_count >= self.MAX_MANUAL_CANDIDATES_TOTAL
            or flow_bytes + message_size
            > self.MAX_MANUAL_CANDIDATE_BYTES_PER_FLOW
            or self._manual_candidate_bytes + message_size
            > self.MAX_MANUAL_CANDIDATE_BYTES_TOTAL
        ):
            # Dropping one contender and then selecting from the survivors can
            # manufacture false uniqueness. Suppress the affected generation
            # until every possibly dropped candidate has naturally expired.
            self._suppress_manual_key_locked(key, now)
            return

        candidate = _ManualDecrementCandidate(
            flow=flow,
            flow_generation=generation,
            stream_start=start,
            stream_end=end,
            timestamp=now,
            opcode=frame.opcode,
            message=bytes(frame.message),
            specs=specs,
        )
        ledger.append(candidate)
        self._manual_candidate_count += 1
        self._manual_candidate_bytes += message_size
        self._manual_candidate_bytes_by_flow[key] = flow_bytes + message_size

    @staticmethod
    def _manual_spec_accepts_message(
        spec: DecrementSpec,
        message: bytes,
    ) -> bool:
        if len(message) < spec.min_message_length:
            return False
        if spec.repeat_stride is None:
            return True
        return (
            len(message) - spec.min_message_length
        ) % spec.repeat_stride == 0

    def _activate_manual_generation_locked(
        self,
        flow: FlowKey,
        generation: int,
    ) -> bool:
        active = self._manual_active_generations.get(flow)
        if active is None:
            self._manual_active_generations[flow] = generation
            return True
        if generation == active:
            return True
        if generation < active:
            return False
        self._purge_manual_flow_locked(flow)
        self._manual_active_generations[flow] = generation
        return True

    def _manual_key_is_suppressed_locked(self, key: _ManualFlowKey) -> bool:
        suppressed_until = self._manual_suppressed_until.get(key)
        if suppressed_until is None:
            return False
        latest = self._manual_latest_timestamps.get(key, suppressed_until)
        if latest <= suppressed_until:
            return True
        self._manual_suppressed_until.pop(key, None)
        return False

    def _suppress_manual_key_locked(
        self,
        key: _ManualFlowKey,
        timestamp: float,
    ) -> None:
        suppression_clock = max(
            timestamp,
            self._manual_latest_timestamps.get(key, timestamp),
        )
        self._manual_suppressed_until[key] = max(
            self._manual_suppressed_until.get(key, suppression_clock),
            suppression_clock + self.STALE_SECONDS,
        )

    def _prune_manual_candidates_locked(self, now: float) -> None:
        for key, candidates in tuple(self._manual_candidates.items()):
            retained: deque[_ManualDecrementCandidate] = deque()
            removed_count = 0
            removed_bytes = 0
            for candidate in candidates:
                if now - candidate.timestamp > self.STALE_SECONDS:
                    removed_count += 1
                    removed_bytes += candidate.message_length
                else:
                    retained.append(candidate)
            if retained:
                self._manual_candidates[key] = retained
            else:
                self._manual_candidates.pop(key, None)
            if removed_count:
                self._manual_candidate_count -= removed_count
                self._manual_candidate_bytes -= removed_bytes
                remaining_bytes = (
                    self._manual_candidate_bytes_by_flow.get(key, 0)
                    - removed_bytes
                )
                if remaining_bytes:
                    self._manual_candidate_bytes_by_flow[key] = remaining_bytes
                else:
                    self._manual_candidate_bytes_by_flow.pop(key, None)

        for key, suppressed_until in tuple(
            self._manual_suppressed_until.items()
        ):
            latest = max(
                now,
                self._manual_latest_timestamps.get(key, now),
            )
            if latest > suppressed_until:
                self._manual_suppressed_until.pop(key, None)

    def _reserve_matching_decrement(
        self,
        flow: FlowKey,
        flow_generation: int,
        stream_sequence: Optional[int],
        events: tuple[BDOEvent, ...],
    ) -> list[tuple[int, _ManualDecrementMatch]]:
        """Uniquely assign one physical decrement to one storage wrapper."""

        if stream_sequence is None or not events:
            return []
        if not self._activate_manual_generation_locked(flow, flow_generation):
            return []
        key = (flow, flow_generation)
        event = events[0]
        self._manual_latest_timestamps[key] = max(
            event.timestamp,
            self._manual_latest_timestamps.get(key, event.timestamp),
        )
        self._prune_manual_candidates_locked(event.timestamp)
        if self._manual_key_is_suppressed_locked(key):
            return []

        operation_key: _ManualOperationKey = (
            flow,
            flow_generation,
            stream_sequence,
            event.opcode,
            event.message_length,
            event.timestamp,
        )
        evaluated: list[
            tuple[
                tuple[int, int, int],
                _ManualDecrementCandidate,
                list[tuple[int, _ManualDecrementMatch]],
            ]
        ] = []
        for candidate in self._manual_candidates.get(key, ()):
            if candidate.reserved_by is not None:
                continue
            if candidate.stream_end > stream_sequence:
                continue
            if event.timestamp - candidate.timestamp > self.STALE_SECONDS:
                continue
            result = self._manual_candidate_group_match(
                candidate,
                events,
                stream_sequence,
            )
            if result is None:
                continue
            score, matches = result
            evaluated.append((score, candidate, matches))

        if not evaluated:
            return []
        best_score = min(entry[0] for entry in evaluated)
        winners = [entry for entry in evaluated if entry[0] == best_score]
        if len(winners) != 1:
            # These candidates were all equally attributable to this wrapper.
            # Leaving them free would let a later operation manufacture a
            # unique match merely because another contender was consumed.
            for _score, candidate, _matches in winners:
                candidate.reserved_by = operation_key
            return []
        _score, candidate, matches = winners[0]
        candidate.reserved_by = operation_key
        return matches

    def _manual_candidate_group_match(
        self,
        candidate: _ManualDecrementCandidate,
        events: tuple[BDOEvent, ...],
        storage_sequence: int,
    ) -> Optional[
        tuple[tuple[int, int, int], list[tuple[int, _ManualDecrementMatch]]]
    ]:
        rank = {"observed": 0, "structural": 1, "heuristic": 2}
        compatible_ranks: list[int] = []
        selected: list[
            tuple[
                int,
                tuple[int, Optional[int]],
                _ManualDecrementMatch,
            ]
        ] = []
        for fallback_index, event in enumerate(events, 1):
            choices = self._manual_candidate_record_matches(
                candidate,
                event,
                storage_sequence,
            )
            if not choices:
                continue
            compatible_ranks.append(rank[choices[0][1].confidence])
            if len(choices) != 1:
                continue
            record_key, match = choices[0]
            selected.append(
                (event.record_index or fallback_index, record_key, match)
            )

        # One source record cannot prove two destination records. A repeated
        # quantity without identity is therefore ambiguous inside a batch.
        record_key_counts: dict[tuple[int, Optional[int]], int] = {}
        for _event_index, record_key, _match in selected:
            record_key_counts[record_key] = record_key_counts.get(record_key, 0) + 1
        unique = [
            (event_index, match)
            for event_index, record_key, match in selected
            if record_key_counts[record_key] == 1
        ]
        if not compatible_ranks:
            return None

        best_rank = min(compatible_ranks)
        best_count = compatible_ranks.count(best_rank)
        # Strength dominates. At equal strength, broader compatible coverage
        # wins; recency is intentionally not a tie-breaker.
        score = (best_rank, -best_count, -len(compatible_ranks))
        return score, unique

    def _manual_candidate_record_matches(
        self,
        candidate: _ManualDecrementCandidate,
        event: BDOEvent,
        storage_sequence: int,
    ) -> list[
        tuple[tuple[int, Optional[int]], _ManualDecrementMatch]
    ]:
        quantity_bytes = event.quantity.to_bytes(4, "little")
        destination_instance = self._event_storage_instance(event)
        matches: dict[
            tuple[int, Optional[int]],
            _ManualDecrementMatch,
        ] = {}
        rank = {"observed": 0, "structural": 1, "heuristic": 2}

        for spec in candidate.specs:
            inferred_repeat_stride: Optional[int] = None
            if spec.repeat_stride is not None:
                extra_length = candidate.message_length - spec.min_message_length
                record_deltas: Iterable[int] = range(
                    0,
                    extra_length + 1,
                    spec.repeat_stride,
                )
            elif (
                spec.source_instance_offset is not None
                and destination_instance is not None
                and isinstance(event.record_index, int)
                and not isinstance(event.record_index, bool)
                and isinstance(event.record_count, int)
                and not isinstance(event.record_count, bool)
                and event.record_count > 1
                and 1 <= event.record_index <= event.record_count
            ):
                # Older profiles predate repeat_stride. Batch cardinality can
                # recover it only when exact identity validates inferred
                # nonzero records; quantity-only evidence never expands.
                extra_length = candidate.message_length - spec.min_message_length
                divisor = event.record_count - 1
                if extra_length <= 0 or extra_length % divisor:
                    record_deltas = (0,)
                else:
                    inferred_stride = extra_length // divisor
                    prefix_length = spec.min_message_length - inferred_stride
                    if (
                        inferred_stride <= 0
                        or prefix_length < 5
                        or spec.quantity_offset < prefix_length
                        or spec.source_instance_offset < prefix_length
                    ):
                        record_deltas = (0,)
                    else:
                        inferred_repeat_stride = inferred_stride
                        record_deltas = range(
                            0,
                            extra_length + 1,
                            inferred_stride,
                        )
            else:
                record_deltas = (0,)

            for delta in record_deltas:
                quantity_offset = spec.quantity_offset + delta
                quantity_end = quantity_offset + 4
                if (
                    quantity_end > candidate.message_length
                    or candidate.message[quantity_offset:quantity_end]
                    != quantity_bytes
                ):
                    continue

                source_offset = spec.source_instance_offset
                record_key: tuple[int, Optional[int]]
                if source_offset is None:
                    if not self._quantity_only_is_immediate(
                        candidate,
                        storage_sequence,
                    ):
                        continue
                    match = _ManualDecrementMatch(
                        opcode=candidate.opcode,
                        message_length=candidate.message_length,
                        quantity_offset=quantity_offset,
                        source_instance_offset=None,
                        match_kind="quantity-only",
                        confidence="heuristic",
                        instance_matches_destination=None,
                    )
                    record_key = (quantity_offset, None)
                else:
                    source_offset += delta
                    source_end = source_offset + 8
                    if source_end > candidate.message_length:
                        continue
                    source_instance = bytes(
                        candidate.message[source_offset:source_end]
                    )
                    if not self._nonempty_source_instance(source_instance):
                        continue
                    exact = (
                        destination_instance is not None
                        and source_instance == destination_instance
                    )
                    if not exact:
                        if inferred_repeat_stride is not None and delta:
                            continue
                        if not self._structural_source_instance(source_instance):
                            continue
                    match = _ManualDecrementMatch(
                        opcode=candidate.opcode,
                        message_length=candidate.message_length,
                        quantity_offset=quantity_offset,
                        source_instance_offset=source_offset,
                        match_kind=(
                            "instance-and-quantity"
                            if exact
                            else "anchored-instance-and-quantity"
                        ),
                        confidence="observed" if exact else "structural",
                        instance_matches_destination=(
                            exact if destination_instance is not None else None
                        ),
                    )
                    record_key = (quantity_offset, source_offset)

                previous = matches.get(record_key)
                if previous is None or rank[match.confidence] < rank[
                    previous.confidence
                ]:
                    matches[record_key] = match

        if not matches:
            return []
        best_rank = min(rank[match.confidence] for match in matches.values())
        return [
            (record_key, match)
            for record_key, match in matches.items()
            if rank[match.confidence] == best_rank
        ]

    def _quantity_only_is_immediate(
        self,
        candidate: _ManualDecrementCandidate,
        storage_sequence: int,
    ) -> bool:
        intervening = sum(
            successor < storage_sequence
            for successor in candidate.successor_starts
        )
        return intervening < self.MANUAL_IMMEDIATE_SUCCESSORS

    @staticmethod
    def _event_storage_instance(event: BDOEvent) -> Optional[bytes]:
        value = event.storage_instance
        if not isinstance(value, str) or not value.startswith("0x"):
            return None
        try:
            decoded = bytes.fromhex(value[2:])
        except ValueError:
            return None
        return decoded if len(decoded) == 8 else None

    @staticmethod
    def _nonempty_source_instance(value: bytes) -> bool:
        return len(value) == 8 and value not in (b"\x00" * 8, b"\xff" * 8)

    @classmethod
    def _structural_source_instance(cls, value: bytes) -> bool:
        if not cls._nonempty_source_instance(value):
            return False
        empty_halves = {b"\x00" * 4, b"\xff" * 4}
        return value[:4] not in empty_halves and value[4:] not in empty_halves

    def _remove_manual_key_locked(self, key: _ManualFlowKey) -> None:
        candidates = self._manual_candidates.pop(key, ())
        removed_count = len(candidates)
        removed_bytes = sum(
            candidate.message_length for candidate in candidates
        )
        self._manual_candidate_count -= removed_count
        self._manual_candidate_bytes -= removed_bytes
        self._manual_candidate_bytes_by_flow.pop(key, None)
        self._manual_frame_frontiers.pop(key, None)
        self._manual_reset_floors.pop(key, None)
        self._manual_latest_timestamps.pop(key, None)
        self._manual_suppressed_until.pop(key, None)

    def _purge_manual_flow_locked(self, flow: FlowKey) -> None:
        keys = {
            key
            for mapping in (
                self._manual_candidates,
                self._manual_candidate_bytes_by_flow,
                self._manual_frame_frontiers,
                self._manual_reset_floors,
                self._manual_latest_timestamps,
                self._manual_suppressed_until,
            )
            for key in mapping
            if key[0] == flow
        }
        for key in keys:
            self._remove_manual_key_locked(key)
        self._manual_active_generations.pop(flow, None)

    def reset(self, flow: FlowKey, flow_generation: int, resume_sequence: int) -> None:
        key = (flow, flow_generation)
        if self._manual_active_generations.get(flow) not in (
            None,
            flow_generation,
        ):
            return
        self._remove_manual_key_locked(key)
        self._manual_active_generations[flow] = flow_generation
        self._manual_reset_floors[key] = max(
            resume_sequence,
            self._manual_reset_floors.get(key, resume_sequence),
        )
        self._manual_frame_frontiers[key] = max(
            resume_sequence,
            self._manual_frame_frontiers.get(key, resume_sequence),
        )

    def clear(self) -> None:
        self._manual_candidates.clear()
        self._manual_candidate_count = 0
        self._manual_candidate_bytes = 0
        self._manual_candidate_bytes_by_flow.clear()
        self._manual_active_generations.clear()
        self._manual_frame_frontiers.clear()
        self._manual_reset_floors.clear()
        self._manual_latest_timestamps.clear()
        self._manual_suppressed_until.clear()
