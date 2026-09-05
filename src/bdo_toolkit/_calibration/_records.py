"""Private calibration records implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional
from .._record_geometry import uniform_stride
from .._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    LOOT_PREVIEW_SENTINEL_INSTANCE,
    MAX_PLAUSIBLE_ITEM_ID,
    SOURCE_CONTEXT_LABELS,
    STORAGE_DELTA_CONTEXTS,
    storage_destination_candidates,
)
from ._constants import REFERENCE_FRAME_MAX_LENGTH


class _FrameIndex:
    """One-pass same-flow position index for calibration context lookups."""

    def __init__(self, frames: list[BDOFrame]) -> None:
        by_flow: dict[tuple[object, int], list[BDOFrame]] = {}
        positions: dict[
            int,
            Optional[tuple[tuple[object, int], int]],
        ] = {}
        for frame in frames:
            flow_identity = (
                frame.context.flow,
                frame.context.flow_generation,
            )
            flow_frames = by_flow.setdefault(flow_identity, [])
            identity = id(frame)
            location = (flow_identity, len(flow_frames))
            positions[identity] = (
                location if identity not in positions else None
            )
            flow_frames.append(frame)
        self._by_flow = {
            flow: tuple(flow_frames) for flow, flow_frames in by_flow.items()
        }
        self._positions = positions

    def context_before(
        self,
        target_frame: BDOFrame,
        context_frames: int,
    ) -> tuple[BDOFrame, ...]:
        if context_frames <= 0:
            return ()
        flow_identity = (
            target_frame.context.flow,
            target_frame.context.flow_generation,
        )
        flow_frames = self._by_flow.get(flow_identity, ())
        has_identity = id(target_frame) in self._positions
        location = self._positions.get(id(target_frame))
        index = None if location is None else location[1]
        if not has_identity:
            # Public helpers may be passed an equal reconstructed frame rather
            # than the exact object from ``frames``. Accept one unambiguous
            # equality match; fail closed if multiple positions compare equal.
            matches = tuple(
                candidate_index
                for candidate_index, candidate in enumerate(flow_frames)
                if candidate == target_frame
            )
            index = matches[0] if len(matches) == 1 else None
        if index is None:
            return ()
        return flow_frames[max(0, index - context_frames) : index]


@dataclass(frozen=True)
class _Options:
    item_id: int
    quantity: Optional[int]
    action: str
    context_frames: int
    min_confidence: float
    frame_index: Optional[_FrameIndex] = None


@dataclass(frozen=True)
class _CalibratedItemRecord:
    frame: BDOFrame
    item_offset: int
    item_id: int
    quantity: int
    instance_offset: Optional[int]
    instance: Optional[bytes]
    confidence: float
    reasons: tuple[str, ...]


def _find_calibration_item_records(
    frames: list[BDOFrame],
    options: _Options,
    action: str,
    ignored: list[str],
) -> list[_CalibratedItemRecord]:
    item_bytes = options.item_id.to_bytes(4, "little")
    records: list[_CalibratedItemRecord] = []

    for frame in frames:
        frame_quantity_total = _sum_plausible_item_record_quantities(
            frame,
            item_bytes,
        )
        quantity_only = (
            options.quantity is not None
            and options.quantity.to_bytes(4, "little") in frame.message
            and item_bytes not in frame.message
        )
        if quantity_only:
            ignored.append(
                f'IGNORED opcode=0x{frame.opcode:04X} length={frame.length} '
                'reason="quantity-only"'
            )

        search_at = 0
        while True:
            item_offset = frame.message.find(item_bytes, search_at)
            if item_offset < 0:
                break
            search_at = item_offset + 1

            if item_offset + 8 > len(frame.message):
                ignored.append(
                    f'IGNORED opcode=0x{frame.opcode:04X} length={frame.length} '
                    f'item_offset={item_offset} reason="truncated-item-record"'
                )
                continue

            quantity = int.from_bytes(
                frame.message[item_offset + 4 : item_offset + 8],
                "little",
            )
            instance_offset = item_offset + 35
            instance = (
                bytes(frame.message[instance_offset : instance_offset + 8])
                if instance_offset + 8 <= len(frame.message)
                else None
            )
            confidence, reasons = _score_item_record_candidate(
                frame=frame,
                quantity=quantity,
                instance=instance,
                options=options,
                action=action,
                frame_quantity_total=frame_quantity_total,
            )
            if not _passes_min_confidence(confidence, options.min_confidence):
                ignored.append(
                    f'IGNORED opcode=0x{frame.opcode:04X} length={frame.length} '
                    f'item_offset={item_offset} reason="low-confidence:{confidence:.2f}"'
                )
                continue

            records.append(
                _CalibratedItemRecord(
                    frame=frame,
                    item_offset=item_offset,
                    item_id=options.item_id,
                    quantity=quantity,
                    instance_offset=instance_offset if instance is not None else None,
                    instance=instance,
                    confidence=confidence,
                    reasons=tuple(reasons),
                )
            )

    return records


def _passes_min_confidence(confidence: float, min_confidence: float) -> bool:
    return confidence + 1e-9 >= min_confidence


def _score_item_record_candidate(
    *,
    frame: BDOFrame,
    quantity: int,
    instance: Optional[bytes],
    options: _Options,
    action: str,
    frame_quantity_total: Optional[int],
) -> tuple[float, list[str]]:
    score = 0.35
    reasons = ["contains-watched-item"]

    if 0 < quantity <= 1_000_000:
        reasons.append("plausible-quantity")
        if options.quantity is None:
            score += 0.15
        elif quantity == options.quantity:
            score += 0.25
            reasons.append("quantity-match")
        elif frame_quantity_total == options.quantity:
            score += 0.20
            reasons.append("multi-record-total-quantity-match")
        else:
            score -= 0.20
            reasons.append("quantity-mismatch")
    else:
        score -= 0.30
        reasons.append("implausible-quantity")

    if instance is not None:
        score += 0.20
        reasons.append("instance-present")
    else:
        score -= 0.20
        reasons.append("instance-missing")

    if 200 <= frame.length <= 300:
        score += 0.10
        reasons.append("plausible-wrapper-length")

    score += 0.10
    reasons.append(f"action-window:{action}")

    if action == "loot-preview":
        if instance == LOOT_PREVIEW_SENTINEL_INSTANCE:
            score += 0.10
            reasons.append("preview-sentinel-instance")
        else:
            score -= 0.20
            reasons.append("preview-instance-not-sentinel")
    elif action in {"storage-to-inventory", "inventory-to-storage"}:
        if instance == LOOT_PREVIEW_SENTINEL_INSTANCE:
            score -= 0.20
            reasons.append("real-transfer-has-preview-sentinel")

    if instance is None and frame.length < 100:
        score -= 0.20
        reasons.append("tiny-hit-without-instance")

    return max(0.0, min(1.0, score)), reasons


def _plausible_record_offsets(frame: BDOFrame, item_bytes: bytes) -> list[int]:
    """Offsets of plausible watched-item records (item id + qty + instance)."""
    offsets: list[int] = []
    search_at = 0
    while True:
        item_offset = frame.message.find(item_bytes, search_at)
        if item_offset < 0:
            return offsets
        search_at = item_offset + 1
        if item_offset + 43 > len(frame.message):
            continue
        quantity = int.from_bytes(
            frame.message[item_offset + 4 : item_offset + 8], "little"
        )
        instance = frame.message[item_offset + 35 : item_offset + 43]
        if 0 < quantity <= 1_000_000 and _is_plausible_instance(instance):
            offsets.append(item_offset)


def _sum_plausible_item_record_quantities(
    frame: BDOFrame,
    item_bytes: bytes,
) -> Optional[int]:
    offsets = _plausible_record_offsets(frame, item_bytes)
    if not offsets:
        return None
    return sum(
        int.from_bytes(frame.message[offset + 4 : offset + 8], "little")
        for offset in offsets
    )


def _record_frame_shape(
    frame: BDOFrame,
    item_id: int,
    item_offset: int,
    instance_offset: Optional[int],
) -> tuple[int, Optional[int]]:
    """``(single_record_length, stride)`` for a repeated-record frame.

    A frame carrying N watched-item records at a uniform stride (unstackables
    move as N records of quantity 1) must be written into the profile at its
    SINGLE-record length: the profile loader treats the recorded length as a
    minimum message length, so writing the observed multi-record length would
    produce a profile that cannot decode ordinary single transfers.

    Full transfer-record markers are used first so mixed-item batches can be
    normalized too. Repeated watched-item offsets remain as a fallback for
    older layouts without those markers.
    """
    offsets = _full_transfer_record_offsets(frame, item_offset, instance_offset)
    if len(offsets) < 2:
        offsets = _plausible_record_offsets(frame, item_id.to_bytes(4, "little"))
    if len(offsets) < 2:
        return frame.length, None
    stride = uniform_stride(offsets)
    if stride is None:
        return frame.length, None
    return frame.length - (len(offsets) - 1) * stride, stride


def _first_transfer_record_layout(
    frame: BDOFrame,
    item_offset: int,
    instance_offset: Optional[int],
) -> tuple[int, Optional[int]]:
    """Normalize a watched later batch item back to record zero's offsets."""
    if instance_offset is None:
        return item_offset, None
    instance_delta = instance_offset - item_offset
    offsets = _full_transfer_record_offsets(frame, item_offset, instance_offset)
    if not offsets:
        return item_offset, instance_offset
    first_item_offset = offsets[0]
    return first_item_offset, first_item_offset + instance_delta


def _full_transfer_record_offsets(
    frame: BDOFrame,
    item_offset: int,
    instance_offset: Optional[int],
) -> list[int]:
    """Locate structurally complete item records, including mixed-item batches."""
    if instance_offset is None:
        return []
    instance_delta = instance_offset - item_offset
    if instance_delta < 8:
        return []
    return [
        offset
        for offset in range(5, len(frame.message))
        if _looks_like_transfer_record(frame, offset, instance_delta)
    ]


def _looks_like_transfer_record(
    frame: BDOFrame,
    item_offset: int,
    instance_delta: int,
) -> bool:
    required_end = item_offset + max(20, instance_delta + 8)
    if required_end > len(frame.message):
        return False
    item_id = int.from_bytes(frame.message[item_offset : item_offset + 4], "little")
    quantity = int.from_bytes(
        frame.message[item_offset + 4 : item_offset + 8], "little"
    )
    instance = bytes(
        frame.message[
            item_offset + instance_delta : item_offset + instance_delta + 8
        ]
    )
    return (
        0 < item_id <= MAX_PLAUSIBLE_ITEM_ID
        and 0 < quantity <= 1_000_000
        and _is_plausible_instance(instance)
        and frame.message[item_offset + 8 : item_offset + 12] == b"\x00" * 4
        and frame.message[item_offset + 12 : item_offset + 20] == b"\xff" * 8
    )


def _source_container_structural_instance_offset(
    frame: BDOFrame,
    quantity_offset: int,
) -> Optional[int]:
    """Recognize the legacy ``instance + separator + quantity`` layout."""
    instance_offset = quantity_offset - 9
    separator = frame.message[quantity_offset - 1 : quantity_offset]
    if instance_offset < 5 or separator != b"\x02":
        return None
    instance = frame.message[instance_offset : instance_offset + 8]
    return instance_offset if _is_structural_source_instance(instance) else None


def _source_stack_structural_instance_offset(
    frame: BDOFrame,
    quantity_offset: int,
) -> Optional[int]:
    """Recognize known pre- and post-quantity source-instance layouts.

    The older family places the instance immediately before quantity. The
    current family uses ``quantity + uint32(0) + instance``. If a frame happens
    to satisfy both shapes, the instance remains unproven.
    """
    offsets: set[int] = set()

    before_offset = quantity_offset - 8
    if before_offset >= 5 and _is_structural_source_instance(
        frame.message[before_offset:quantity_offset]
    ):
        offsets.add(before_offset)

    after_offset = quantity_offset + 8
    if (
        after_offset + 8 <= frame.length
        and frame.message[quantity_offset + 4 : after_offset] == b"\x00" * 4
        and _is_structural_source_instance(
            frame.message[after_offset : after_offset + 8]
        )
    ):
        offsets.add(after_offset)

    return next(iter(offsets)) if len(offsets) == 1 else None


def _is_structural_source_instance(value: bytes) -> bool:
    """Stronger guard for an uncorrelated instance-shaped field.

    Exact cross-frame matches use the broader instance validator. A field
    inferred only from layout must have entropy in both uint32 halves; this
    rejects current frames' incidental ``uint32(0) + small value`` at q-8.
    """
    if not _is_plausible_instance(value):
        return False
    empty_halves = {b"\x00" * 4, b"\xff" * 4}
    return value[:4] not in empty_halves and value[4:] not in empty_halves


def _ranges_overlap(
    first_offset: int,
    first_width: int,
    second_offset: int,
    second_width: int,
) -> bool:
    return (
        first_offset < second_offset + second_width
        and second_offset < first_offset + first_width
    )


def _is_source_item_reference(frame: BDOFrame, item_bytes: bytes) -> bool:
    """Whether a small frame carries a non-record reference to the item."""
    if not 20 <= frame.length <= REFERENCE_FRAME_MAX_LENGTH:
        return False
    return any(
        not _looks_like_full_item_record(frame, item_offset)
        for item_offset in _find_all(frame.message, item_bytes)
    )


def _context_before(
    frame_index: _FrameIndex,
    target_frame: BDOFrame,
    context_frames: int,
) -> list[BDOFrame]:
    return list(frame_index.context_before(target_frame, context_frames))


def _discover_context_offset(frame: BDOFrame, before_offset: int) -> Optional[int]:
    best_offset = None
    for context_bytes in SOURCE_CONTEXT_LABELS:
        if (
            context_bytes == CHARACTER_LOAD_CONTEXT
            or context_bytes in STORAGE_DELTA_CONTEXTS
        ):
            continue
        search_at = 0
        while True:
            offset = frame.message.find(context_bytes, search_at)
            if offset < 0:
                break
            if offset < before_offset:
                best_offset = offset if best_offset is None else max(best_offset, offset)
            search_at = offset + 1
    return best_offset


def _discover_source_container_trailing_context_offset(
    frame: BDOFrame,
    after_offset: int,
) -> Optional[int]:
    """Return one unique source context after a container quantity field.

    This is deliberately narrower than ``_discover_context_offset``. The
    caller requires an exact receipt-instance match before using this fallback,
    and ambiguity among trailing context labels fails closed.
    """

    offsets: set[int] = set()
    for context_bytes in SOURCE_CONTEXT_LABELS:
        if (
            context_bytes == CHARACTER_LOAD_CONTEXT
            or context_bytes in STORAGE_DELTA_CONTEXTS
        ):
            continue
        search_at = max(5, after_offset)
        while True:
            offset = frame.message.find(context_bytes, search_at)
            if offset < 0:
                break
            offsets.add(offset)
            search_at = offset + 1
    return next(iter(offsets)) if len(offsets) == 1 else None


def _discover_storage_context_offset(
    frame: BDOFrame,
    before_offset: int,
) -> Optional[int]:
    """Return one unambiguous town column in a structurally valid wrapper."""
    if not _has_dynamic_storage_record_geometry(frame, before_offset):
        return None
    candidates = storage_destination_candidates(
        frame.message,
        before_offset=before_offset,
    )
    if len(candidates) == 1:
        return candidates[0][0]
    return None


def _discover_storage_context_offset_from_frames(
    frames: Iterable[BDOFrame],
    *,
    opcode: int,
    item_offset: int,
) -> Optional[int]:
    """Learn the destination column by cross-frame offset consistency.

    This intentionally assumes neither the byte envelope around a town ID nor
    an item-relative position.  Registered-ID overlaps disappear when the
    same field column is intersected across different destination values.
    """

    candidate_intersection: Optional[set[int]] = None
    unregistered_messages: list[bytes] = []
    messages_seen: set[bytes] = set()
    for frame in frames:
        if (
            frame.opcode != opcode
            or frame.message in messages_seen
            or not _has_dynamic_storage_record_geometry(frame, item_offset)
        ):
            continue
        candidates = {
            offset
            for offset, _storage_id in storage_destination_candidates(
                frame.message,
                before_offset=item_offset,
            )
        }
        messages_seen.add(frame.message)
        if not candidates:
            # A newly added town can be structurally valid before the toolkit
            # name registry knows its numeric key. Let registered destinations
            # establish the column, then require that same column to contain a
            # nonzero uint32 here. An unknown town must not veto an otherwise
            # provable patch schema or be relabeled from a decoy elsewhere.
            unregistered_messages.append(frame.message)
            continue
        candidate_intersection = (
            candidates
            if candidate_intersection is None
            else candidate_intersection & candidates
        )
        if not candidate_intersection:
            return None
    if candidate_intersection is None or len(candidate_intersection) != 1:
        return None
    selected = next(iter(candidate_intersection))
    if any(
        selected + 4 > item_offset
        or int.from_bytes(message[selected : selected + 4], "little") == 0
        for message in unregistered_messages
    ):
        return None
    return selected


def _has_dynamic_storage_record_geometry(
    frame: BDOFrame,
    item_offset: int,
) -> bool:
    """Whether some prefix count proves every full storage item record."""

    if item_offset + 43 > frame.length:
        return False
    geometries: set[tuple[int, int]] = set()
    for count_offset in range(5, max(5, item_offset - 1)):
        count = int.from_bytes(
            frame.message[count_offset : count_offset + 2],
            "little",
        )
        if count <= 0:
            continue
        for prefix_length in range(max(5, count_offset + 2), item_offset + 1):
            record_bytes = frame.length - prefix_length
            if record_bytes <= 0 or record_bytes % count:
                continue
            stride = record_bytes // count
            relative_item_offset = item_offset - prefix_length
            if relative_item_offset < 0 or relative_item_offset + 43 > stride:
                continue
            if all(
                _looks_like_full_item_record(
                    frame,
                    item_offset + index * stride,
                )
                for index in range(count)
            ):
                geometries.add((count, stride))
    return bool(geometries)


def _discover_storage_record_count_offset(
    frames: Iterable[BDOFrame],
    *,
    records: Iterable[_CalibratedItemRecord],
    opcode: int,
    item_offset: int,
    instance_offset: Optional[int],
    single_record_length: int,
) -> Optional[int]:
    """Learn one authoritative uint16 count column from record geometry.

    A single wrapper can contain another small integer equal to its item
    count.  Intersecting candidates across independently validated frames and
    count shapes prevents such a field from silently impersonating the real
    declaration.  No absolute or item-relative count position is assumed.
    """

    if instance_offset is None:
        return None
    records_by_message: dict[bytes, list[int]] = {}
    for record in records:
        if record.frame.opcode != opcode:
            continue
        records_by_message.setdefault(record.frame.message, []).append(
            record.item_offset
        )
    candidate_intersection: Optional[set[int]] = None
    messages_seen: set[bytes] = set()
    counts_seen: set[int] = set()
    for frame in frames:
        if frame.opcode != opcode or frame.message in messages_seen:
            continue
        offsets = _full_transfer_record_offsets(
            frame,
            item_offset,
            instance_offset,
        )
        if not offsets:
            offsets = sorted(set(records_by_message.get(frame.message, ())))
        if not offsets or offsets[0] != item_offset:
            continue
        count = len(offsets)
        if count == 1:
            if frame.length != single_record_length:
                continue
        else:
            stride = uniform_stride(offsets)
            if stride is None:
                continue
            if frame.length - (count - 1) * stride != single_record_length:
                continue

        search_end = min(item_offset, len(frame.message))
        candidates = {
            offset
            for offset in range(5, max(5, search_end - 1))
            if int.from_bytes(frame.message[offset : offset + 2], "little")
            == count
        }
        if not candidates:
            return None
        messages_seen.add(frame.message)
        counts_seen.add(count)
        candidate_intersection = (
            candidates
            if candidate_intersection is None
            else candidate_intersection & candidates
        )
        if not candidate_intersection:
            return None

    # One count shape cannot distinguish the declaration from an unrelated
    # header integer that happens to carry the same value. Two independently
    # validated shapes are the minimum patch-agnostic semantic proof.
    if (
        len(counts_seen) < 2
        or candidate_intersection is None
        or len(candidate_intersection) != 1
    ):
        return None
    return next(iter(candidate_intersection))


def _looks_like_full_item_record(frame: BDOFrame, item_offset: int) -> bool:
    if item_offset + 43 > len(frame.message):
        return False
    quantity = int.from_bytes(frame.message[item_offset + 4 : item_offset + 8], "little")
    instance = frame.message[item_offset + 35 : item_offset + 43]
    return 0 < quantity <= 1_000_000 and _is_plausible_instance(instance)


def _is_plausible_instance(value: bytes) -> bool:
    return len(value) == 8 and value != b"\x00" * 8 and value != b"\xff" * 8


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    search_at = 0
    while True:
        offset = haystack.find(needle, search_at)
        if offset < 0:
            return offsets
        offsets.append(offset)
        search_at = offset + 1
