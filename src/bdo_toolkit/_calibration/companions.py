"""Private calibration companions implementation."""

from __future__ import annotations

from typing import Iterable, Optional
from .._protocol import BDOFrame
from ._constants import REFERENCE_FRAME_MAX_LENGTH, SOURCE_DECREMENT_FRAME_MAX_LENGTH
from ._formatting import _calibration_source, _confidence_label, _iso_timestamp
from ._records import (
    _CalibratedItemRecord,
    _FrameIndex,
    _Options,
    _context_before,
    _discover_context_offset,
    _discover_source_container_trailing_context_offset,
    _find_all,
    _full_transfer_record_offsets,
    _is_plausible_instance,
    _is_source_item_reference,
    _looks_like_full_item_record,
    _ranges_overlap,
    _source_container_structural_instance_offset,
    _source_stack_structural_instance_offset,
)
from .models import MessageSpec


def _discover_source_container_decrement(
    frames: list[BDOFrame],
    receipt: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    """Find the storage-side decrement that precedes an inventory receipt.

    Companion layouts have changed field order across patches, so neither the
    source instance nor the context is located relative to a fixed field. The
    moved quantity and a source context identify the companion; an exact
    receipt-instance match strengthens the result and supplies its offset.
    """
    item_bytes = receipt.item_id.to_bytes(4, "little")
    quantity_bytes = receipt.quantity.to_bytes(4, "little")
    candidates: list[MessageSpec] = []

    context = _context_before(
        options.frame_index or _FrameIndex(frames),
        receipt.frame,
        options.context_frames,
    )
    for frame in reversed(context):
        if not 20 <= frame.length <= REFERENCE_FRAME_MAX_LENGTH:
            continue
        if item_bytes in frame.message:
            continue
        quantity_offsets = _find_all(frame.message, quantity_bytes)
        if not quantity_offsets:
            continue

        instance_offsets = (
            _find_all(frame.message, receipt.instance)
            if receipt.instance is not None
            else []
        )
        # Multiple occurrences do not prove which field is the source
        # instance. Keep the family calibratable, but omit the uncertain
        # optional offset instead of choosing one by position.
        exact_instance_offset = (
            instance_offsets[0] if len(instance_offsets) == 1 else None
        )

        for quantity_offset in quantity_offsets:
            # Known layouts vary whether context is before or after instance.
            # Historical layouts put context before quantity. A newer layout
            # puts quantity first, so admit a trailing context only when the
            # same frame has one exact receipt-instance anchor; quantity and a
            # context label alone are too weak.
            context_offset = _discover_context_offset(frame, quantity_offset)
            if context_offset is None and exact_instance_offset is not None:
                trailing_context_offset = (
                    _discover_source_container_trailing_context_offset(
                        frame,
                        quantity_offset + 4,
                    )
                )
                if (
                    trailing_context_offset is not None
                    and not _ranges_overlap(
                        exact_instance_offset,
                        8,
                        trailing_context_offset,
                        4,
                    )
                ):
                    context_offset = trailing_context_offset
            if context_offset is None:
                continue
            if exact_instance_offset is not None and _ranges_overlap(
                exact_instance_offset, 8, quantity_offset, 4
            ):
                continue
            structural_instance_offset = _source_container_structural_instance_offset(
                frame, quantity_offset
            )
            instance_offset: Optional[int] = exact_instance_offset
            if instance_offset is not None:
                score = 0.90
            elif structural_instance_offset is not None:
                instance_offset = structural_instance_offset
                score = 0.86
            else:
                score = 0.82
            candidates.append(
                MessageSpec(
                    event="SOURCE_CONTAINER_DECREMENT",
                    opcode=frame.opcode,
                    length=frame.length,
                    context_offset=context_offset,
                    source_instance_offset=instance_offset,
                    quantity_removed_offset=quantity_offset,
                    confidence=_confidence_label(score),
                    source=_calibration_source(options, "storage-to-inventory"),
                    observed_at=_iso_timestamp(frame.context.timestamp),
                    score=score,
                )
            )
    return _unique_best_companion_spec(candidates)


def _discover_source_stack_decrement(
    frames: list[BDOFrame],
    storage_delta: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    """Find the inventory-side decrement that precedes a storage delta.

    Older layouts put the source instance before the quantity; the current
    layout puts it after. Search for the exact instance independently. If it
    cannot be correlated, a unique decrement -> item-reference -> delta chain
    can still identify the family without inventing an instance offset.
    """
    item_bytes = storage_delta.item_id.to_bytes(4, "little")
    quantity = (
        options.quantity
        if options.quantity is not None
        else storage_delta.quantity
    )
    quantity_bytes = quantity.to_bytes(4, "little")
    storage_record_offsets = _full_transfer_record_offsets(
        storage_delta.frame,
        storage_delta.item_offset,
        storage_delta.instance_offset,
    )
    expected_record_count = (
        len(storage_record_offsets) if len(storage_record_offsets) > 1 else None
    )
    context = _context_before(
        options.frame_index or _FrameIndex(frames),
        storage_delta.frame,
        options.context_frames,
    )
    candidates: list[MessageSpec] = []

    for frame_index, frame in enumerate(context):
        if not 20 <= frame.length <= SOURCE_DECREMENT_FRAME_MAX_LENGTH:
            continue
        if item_bytes in frame.message:
            continue
        instance_offsets = (
            _find_all(frame.message, storage_delta.instance)
            if storage_delta.instance is not None
            else []
        )
        exact_instance_offset = (
            instance_offsets[0] if len(instance_offsets) == 1 else None
        )
        if (
            frame.length > REFERENCE_FRAME_MAX_LENGTH
            and exact_instance_offset is None
        ):
            # Wider decrement batches are admitted only through an exact
            # cross-frame instance anchor. Otherwise ordinary context frames
            # carrying common quantities can tie the established compact
            # structural candidate.
            continue
        has_later_reference = any(
            _is_source_item_reference(candidate, item_bytes)
            for candidate in context[frame_index + 1 :]
        )
        if exact_instance_offset is None and not has_later_reference:
            continue

        repeated_shape = _source_stack_repeated_shape(
            frame,
            quantity_bytes,
            exact_instance_offset,
            expected_record_count=expected_record_count,
        )
        if repeated_shape is not None:
            base_length, repeat_stride, instance_offset, quantity_offset = (
                repeated_shape
            )
            candidates.append(
                MessageSpec(
                    event="SOURCE_STACK_DECREMENT",
                    opcode=frame.opcode,
                    length=base_length,
                    repeat_stride=repeat_stride,
                    source_instance_offset=instance_offset,
                    quantity_removed_offset=quantity_offset,
                    confidence=_confidence_label(0.90),
                    source=_calibration_source(options, "inventory-to-storage"),
                    observed_at=_iso_timestamp(frame.context.timestamp),
                    score=0.90,
                )
            )
            continue

        for quantity_offset in _find_all(frame.message, quantity_bytes):
            if exact_instance_offset is not None and _ranges_overlap(
                exact_instance_offset, 8, quantity_offset, 4
            ):
                continue
            structural_instance_offset = _source_stack_structural_instance_offset(
                frame, quantity_offset
            )
            candidate_instance_offset: Optional[int] = exact_instance_offset
            if candidate_instance_offset is not None:
                score = 0.88
            elif structural_instance_offset is not None:
                candidate_instance_offset = structural_instance_offset
                score = 0.86
            else:
                score = 0.82
            candidates.append(
                MessageSpec(
                    event="SOURCE_STACK_DECREMENT",
                    opcode=frame.opcode,
                    length=frame.length,
                    source_instance_offset=candidate_instance_offset,
                    quantity_removed_offset=quantity_offset,
                    confidence=_confidence_label(score),
                    source=_calibration_source(options, "inventory-to-storage"),
                    observed_at=_iso_timestamp(frame.context.timestamp),
                    score=score,
                )
            )
    return _unique_best_companion_spec(candidates)


def _source_stack_repeated_shape(
    frame: BDOFrame,
    quantity_bytes: bytes,
    exact_instance_offset: Optional[int],
    *,
    expected_record_count: Optional[int] = None,
) -> Optional[tuple[int, int, int, int]]:
    """Normalize an instance-anchored decrement batch to record-one geometry.

    The quantity/instance phase is part of the repeated record, not a stable
    patch constant.  Anchor record zero with the exact destination instance,
    try every repeated quantity phase that keeps both fields inside one
    record, and retain only one longest valid geometry.  Longer stride
    multiples can be aliases that skip records; equal-strength distinct
    phases are ambiguous and fail closed.
    """

    if exact_instance_offset is None:
        return None
    if expected_record_count is not None and expected_record_count < 2:
        return None
    quantity_offsets = tuple(sorted(set(_find_all(frame.message, quantity_bytes))))
    if len(quantity_offsets) < 2:
        return None
    quantity_offset_set = set(quantity_offsets)

    # Four quantity bytes and eight instance bytes must coexist without
    # overlap inside one repeated record, so a smaller stride cannot be a
    # valid record geometry. This is a field-width invariant, not a layout
    # constant.
    minimum_stride = 12
    candidates: list[tuple[int, int, int, int]] = []
    for first_quantity_offset in quantity_offsets:
        if _ranges_overlap(
            first_quantity_offset,
            4,
            exact_instance_offset,
            8,
        ):
            continue
        for later_quantity_offset in quantity_offsets:
            repeat_stride = later_quantity_offset - first_quantity_offset
            if repeat_stride < minimum_stride:
                continue

            record_count = 0
            while True:
                delta = record_count * repeat_stride
                quantity_offset = first_quantity_offset + delta
                instance_offset = exact_instance_offset + delta
                if quantity_offset not in quantity_offset_set:
                    break
                if (
                    quantity_offset < 5
                    or quantity_offset + 4 > frame.length
                    or instance_offset < 5
                    or instance_offset + 8 > frame.length
                    or _ranges_overlap(
                        quantity_offset,
                        4,
                        instance_offset,
                        8,
                    )
                    or not _is_plausible_instance(
                        frame.message[instance_offset : instance_offset + 8]
                    )
                ):
                    break
                record_count += 1
            if record_count < 2 or (
                expected_record_count is not None
                and record_count != expected_record_count
            ):
                continue

            prefix_length = frame.length - record_count * repeat_stride
            base_length = prefix_length + repeat_stride
            if (
                prefix_length < 5
                or first_quantity_offset < prefix_length
                or exact_instance_offset < prefix_length
                or first_quantity_offset + 4 > base_length
                or exact_instance_offset + 8 > base_length
            ):
                continue
            candidates.append(
                (
                    record_count,
                    base_length,
                    repeat_stride,
                    first_quantity_offset,
                )
            )

    if not candidates:
        return None
    best_count = max(candidate[0] for candidate in candidates)
    best_shapes = {
        (base_length, repeat_stride, first_quantity_offset)
        for (
            record_count,
            base_length,
            repeat_stride,
            first_quantity_offset,
        ) in candidates
        if record_count == best_count
    }
    if len(best_shapes) != 1:
        return None
    base_length, repeat_stride, first_quantity_offset = next(iter(best_shapes))
    return (
        base_length,
        repeat_stride,
        exact_instance_offset,
        first_quantity_offset,
    )


def _unique_best_companion_spec(
    candidates: Iterable[MessageSpec],
) -> Optional[MessageSpec]:
    """Return one strongest companion candidate, refusing an equal-score tie."""
    unique = {candidate.dedupe_key(): candidate for candidate in candidates}
    if not unique:
        return None
    best_score = max(candidate.score or 0.0 for candidate in unique.values())
    best = [
        candidate
        for candidate in unique.values()
        if (candidate.score or 0.0) == best_score
    ]
    return best[0] if len(best) == 1 else None


def _discover_source_item_reference(
    frames: list[BDOFrame],
    storage_delta: _CalibratedItemRecord,
    options: _Options,
) -> Optional[MessageSpec]:
    item_bytes = storage_delta.item_id.to_bytes(4, "little")

    context = _context_before(
        options.frame_index or _FrameIndex(frames),
        storage_delta.frame,
        options.context_frames,
    )
    for frame in reversed(context):
        if not 20 <= frame.length <= REFERENCE_FRAME_MAX_LENGTH:
            continue
        item_offset = frame.message.find(item_bytes)
        if item_offset < 0:
            continue
        if _looks_like_full_item_record(frame, item_offset):
            continue
        return MessageSpec(
            event="SOURCE_ITEM_REFERENCE",
            opcode=frame.opcode,
            length=frame.length,
            item_id_offset=item_offset,
            confidence=_confidence_label(0.82),
            source=_calibration_source(options, "inventory-to-storage"),
            observed_at=_iso_timestamp(frame.context.timestamp),
            score=0.82,
        )
    return None
