"""Conservative, provisional guidance; never input to layout promotion.

Reuse calibration's structural recognizers, but require stronger per-frame
direction/origin evidence than its batch recovery paths. A missing observation
must not block calibration. No opcode, wizard batch size, or town is assumed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from .._protocol import BDOFrame, FlowKey, SOURCE_CONTEXT_LABELS, storage_destination_candidates
from ._constants import _HIGH_ENTROPY_CONTEXTS
from ._records import (
    _CalibratedItemRecord, _FrameIndex, _Options,
    _find_calibration_item_records,
    _full_transfer_record_offsets, _plausible_record_offsets, _record_frame_shape,
    _storage_clock_alias_status,
)
from .analysis import detect_transfer_family
from .companions import _discover_source_stack_decrement
from .progress import CalibrationObservation


def _linked_decrement(
    record: _CalibratedItemRecord, options: _Options, index: _FrameIndex,
) -> bool:
    context = list(index.context_before(record.frame, options.context_frames))
    # Do not borrow a source decrement from an earlier watched-item transfer.
    item_bytes = options.item_id.to_bytes(4, "little")
    for position in range(len(context) - 1, -1, -1):
        if _plausible_record_offsets(context[position], item_bytes):
            context = context[position + 1:]
            break
    context = [frame for frame in context if frame.length == len(frame.message)]
    frames = [*context, record.frame]
    spec = _discover_source_stack_decrement(
        frames, record, replace(options, frame_index=_FrameIndex(frames)),
    )
    if (spec is None or spec.score is None or spec.score < options.min_confidence
            or spec.source_instance_offset is None or spec.quantity_removed_offset is None):
        return False
    # Structural/reference-only fallback is useful for batch recovery, but is
    # not sufficient to acknowledge a player deposit in a guided UI.
    instance_at, quantity_at = spec.source_instance_offset, spec.quantity_removed_offset
    return any(
        frame.opcode == spec.opcode
        and frame.message[instance_at:instance_at + 8] == record.instance
        and int.from_bytes(frame.message[quantity_at:quantity_at + 4], "little") == record.quantity
        for frame in context
    )


@dataclass(frozen=True)
class _ObservationCandidate:
    position: int
    record: _CalibratedItemRecord
    first_offset: int
    base_length: int
    record_count: int
    watched_count: int
    quantity: int


def _observation_candidates(
    frames: list[BDOFrame], options: _Options,
) -> list[_ObservationCandidate]:
    item_id, quantity = options.item_id, options.quantity
    records = _find_calibration_item_records(frames, options, "inventory-to-storage", [])
    by_frame: dict[int, list[_CalibratedItemRecord]] = {}
    for record in records:
        by_frame.setdefault(id(record.frame), []).append(record)
    accepted = []
    for position, frame in enumerate(frames):
        candidates = by_frame.get(id(frame), [])
        if not candidates or frame.length != len(frame.message):
            continue
        record = candidates[0]
        offsets = _full_transfer_record_offsets(frame, record.item_offset, record.instance_offset)
        watched = [offset for offset in offsets
                   if int.from_bytes(frame.message[offset:offset + 4], "little") == item_id]
        if not watched or record.item_offset != watched[0]:
            continue
        # All watched records must satisfy scoring and exact per-record quantity.
        if set(watched) != {candidate.item_offset for candidate in candidates}:
            continue
        quantities = [int.from_bytes(frame.message[offset + 4:offset + 8], "little")
                      for offset in watched]
        if quantity is not None and any(value != quantity for value in quantities):
            continue
        base_length, stride = _record_frame_shape(frame, item_id, record.item_offset, record.instance_offset)
        # The same plausible single-record envelope used by candidate scoring.
        # Reject partial/irregular multi-record tails instead of undercounting.
        if (not 200 <= base_length <= 300 or (len(offsets) > 1 and stride is None)
                or (stride is not None and stride > base_length)):
            continue
        accepted.append(_ObservationCandidate(
            position, record, offsets[0], base_length,
            len(offsets), len(watched), sum(quantities),
        ))
    return accepted


def _observation_clock_aliases(candidates: list[_ObservationCandidate]) -> dict[int, int]:
    """Compare only complete watched wrappers in one connection and record layout."""
    cohorts: dict[tuple[FlowKey, int, int, int, int], list[BDOFrame]] = {}
    for candidate in candidates:
        frame = candidate.record.frame
        key = (frame.context.flow, frame.context.flow_generation, frame.opcode,
               candidate.first_offset, candidate.base_length)
        cohorts.setdefault(key, []).append(frame)

    excluded = {}
    for (_, _, _, first, _), frames in cohorts.items():
        if len(frames) < 2:
            continue
        columns = storage_destination_candidates(frames[0].message, before_offset=first)
        proven = [
            offset for offset, _ in columns
            if _storage_clock_alias_status(frames, destination_offset=offset, item_offset=first)[1]
        ]
        if len(proven) == 1:
            for frame in frames:
                excluded[id(frame)] = proven[0]
    return excluded


def observe_transfers(
    frames: list[BDOFrame], *, item_id: int, quantity: int | None,
    action: str, context_frames: int, min_confidence: float,
    run_id: str, frames_discarded: int,
) -> tuple[CalibrationObservation, ...]:
    """Replaceable retained-window snapshot, in capture arrival order."""
    if action == "loot-preview":
        return ()
    index = _FrameIndex(frames)
    options = _Options(item_id, quantity, action, context_frames, min_confidence, index)
    candidates = _observation_candidates(frames, options)
    clock_aliases = _observation_clock_aliases(candidates)
    observations = []
    for candidate in candidates:
        record = candidate.record
        frame = record.frame
        excluded_offset = clock_aliases.get(id(frame))
        family, _, _, storage_context = detect_transfer_family(
            frames, frame, candidate.first_offset, item_id, context_frames,
            _frame_index=index, _excluded_storage_offset=excluded_offset,
        )
        direction: Literal["inventory-to-storage", "storage-to-inventory"]
        if family == "into_storage":
            if not storage_context:
                continue
            # A single plausible clock reading may veto this positive observation.
            # It cannot remove a competing column to establish direction.
            columns = storage_destination_candidates(frame.message, before_offset=candidate.first_offset)
            if any(
                _storage_clock_alias_status(
                    [frame], destination_offset=offset, item_offset=candidate.first_offset,
                )[0]
                for offset, _ in columns if offset != excluded_offset
            ):
                continue
            if not _linked_decrement(record, options, index):
                continue
            direction = "inventory-to-storage"
        elif family == "into_inventory":
            # Inventory receipts include loot/gathering/etc. Only an unambiguous
            # Storage source can guide the withdrawal step.
            prefix = frame.message[:candidate.first_offset]
            labels = [SOURCE_CONTEXT_LABELS[raw] for raw in _HIGH_ENTROPY_CONTEXTS
                      for _ in range(prefix.count(raw))]
            if labels != ["Storage"]:
                continue
            direction = "storage-to-inventory"
        else:
            continue
        if action not in ("auto", direction):
            continue
        frame_number = frames_discarded + candidate.position + 1
        observations.append(CalibrationObservation(
            observation_id=f"{run_id}:{frame_number}", frame_number=frame_number,
            direction=direction, opcode=frame.opcode, item_id=item_id,
            record_count=candidate.record_count, item_record_count=candidate.watched_count,
            item_quantity=candidate.quantity,
        ))
    return tuple(observations)
