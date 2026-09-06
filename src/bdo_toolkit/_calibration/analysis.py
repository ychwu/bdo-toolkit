"""Private calibration analysis implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from .._protocol import BDOFrame, LOOT_PREVIEW_SENTINEL_INSTANCE
from ._constants import (
    REFERENCE_FRAME_MAX_LENGTH,
    _EXPECTED_FAMILY,
    _HIGH_ENTROPY_CONTEXTS,
)
from ._formatting import (
    _calibration_source,
    _confidence_label,
    _dedupe_message_specs,
    _iso_timestamp,
)
from ._records import (
    _CalibratedItemRecord,
    _FrameIndex,
    _Options,
    _discover_context_offset,
    _discover_storage_context_offset,
    _discover_storage_context_offset_from_frames,
    _discover_storage_record_count_offset,
    _find_calibration_item_records,
    _first_transfer_record_layout,
    _passes_min_confidence,
    _plausible_record_offsets,
    _record_frame_shape,
)
from .companions import (
    _discover_source_container_decrement,
    _discover_source_item_reference,
    _discover_source_stack_decrement,
    _unique_best_companion_spec,
)
from .models import (
    CalibrationAuthorityError,
    CalibrationResult,
    CalibrationRetention,
    DirectionEvidence,
    DirectionMismatchError,
    MessageSpec,
)
from .validation import _validate_calibration_options


def calibrate_frames(
    frames: list[BDOFrame],
    *,
    item_id: int,
    quantity: Optional[int] = None,
    action: str = "auto",
    context_frames: int = 5,
    min_confidence: float = 0.80,
) -> CalibrationResult:
    """Score collected frames and promote plausible message specs."""
    assessment = assess_frames(
        frames, item_id=item_id, quantity=quantity, action=action,
        context_frames=context_frames, min_confidence=min_confidence,
    )
    if assessment.error is not None:
        raise assessment.error
    return assessment.result


@dataclass(frozen=True)
class FrameAssessment:
    """Internal partial analysis; only the batch facade applies terminal errors."""

    result: CalibrationResult
    error: CalibrationAuthorityError | DirectionMismatchError | None = None


def assess_frames(
    frames: list[BDOFrame],
    *,
    item_id: int,
    quantity: Optional[int] = None,
    action: str = "auto",
    context_frames: int = 5,
    min_confidence: float = 0.80,
) -> FrameAssessment:
    """Use the batch rules while preserving progress from incomplete evidence."""
    _validate_calibration_options(
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
    )

    frame_index = _FrameIndex(frames)
    options = _Options(
        item_id=item_id,
        quantity=quantity,
        action=action,
        context_frames=context_frames,
        min_confidence=min_confidence,
        frame_index=frame_index,
    )
    ignored: list[str] = []
    evidence: list[DirectionEvidence] = []
    specs: list[MessageSpec] = []

    # Auto covers both transfer directions and classifies each from structure.
    # Storage authority additionally needs two distinct record counts so an
    # unrelated small header integer cannot impersonate the count column. Use
    # an unstackable item with quantity=1 and perform at least two different
    # deposit sizes, plus one storage->inventory move. The guided example uses
    # deposits of 1 and 4 followed by one withdrawal of all 5. Direction is
    # never taken on faith. Loot preview needs a gathering action, so it stays
    # an explicit, optional mode.
    actions: tuple[str, ...]
    if action == "auto":
        actions = ("storage-to-inventory", "inventory-to-storage")
        strict = False
    else:
        actions = (action,)
        strict = True

    error = None
    for current_action in actions:
        try:
            if current_action == "loot-preview":
                specs.extend(_calibrate_loot_preview(frames, options, ignored))
            elif current_action == "storage-to-inventory":
                specs.extend(
                    _calibrate_storage_to_inventory(
                        frames, options, ignored, evidence, strict
                    )
                )
            elif current_action == "inventory-to-storage":
                specs.extend(
                    _calibrate_inventory_to_storage(
                        frames, options, ignored, evidence, strict
                    )
                )
        except (CalibrationAuthorityError, DirectionMismatchError) as exc:
            error = exc
            break

    retained_bytes = sum(len(frame.message) for frame in frames)
    return FrameAssessment(CalibrationResult(
        specs=tuple(_dedupe_message_specs(specs)),
        ignored=tuple(ignored),
        frames_scanned=len(frames),
        evidence=tuple(evidence),
        calibration_item_id=item_id,
        retention=CalibrationRetention(
            frames_observed=len(frames),
            frames_retained=len(frames),
            frames_discarded=0,
            bytes_observed=retained_bytes,
            bytes_retained=retained_bytes,
            bytes_discarded=0,
        ),
    ), error)


def _has_context_label_before(frame: BDOFrame, before_offset: int) -> bool:
    for value in _HIGH_ENTROPY_CONTEXTS:
        offset = frame.message.find(value)
        if 0 <= offset < before_offset:
            return True
    return False


def _has_item_reference_frame(
    frame_index: _FrameIndex,
    record_frame: BDOFrame,
    item_id: int,
    context_frames: int,
) -> bool:
    """A small same-flow frame carrying the raw item id, PRECEDING the record.

    Only preceding frames are considered — the reference precedes its record
    in every labeled capture across both opcode generations — and the
    backward scan stops at the first frame that itself carries a plausible
    watched-item record: that frame belongs to an adjacent transaction, and
    its companion frames must not bleed into this record's classification.
    """
    item_bytes = item_id.to_bytes(4, "little")
    for frame in reversed(frame_index.context_before(record_frame, context_frames)):
        if _plausible_record_offsets(frame, item_bytes):
            return False  # adjacent transaction's record frame: boundary
        if frame.length <= REFERENCE_FRAME_MAX_LENGTH and item_bytes in frame.message:
            return True
    return False


def _has_storage_delta_context(frame: BDOFrame, before_offset: int) -> bool:
    """Whether a validated storage destination field precedes the record."""
    return _discover_storage_context_offset(frame, before_offset) is not None


def detect_transfer_family(
    frames: list[BDOFrame],
    record_frame: BDOFrame,
    item_offset: int,
    item_id: int,
    context_frames: int = 5,
    *,
    _frame_index: Optional[_FrameIndex] = None,
) -> tuple[Optional[str], bool, bool, bool]:
    """Classify a record frame's transfer direction, opcode-free.

    Returns ``(family, reference_frame, context_label, storage_context)`` where
    ``family`` is:

    - ``"into_inventory"`` — the record frame carries a high-entropy source
      context label before the item record. The item is entering inventory (a
      receipt: storage pull, mob drop, gathering, mail, ...).
    - ``"into_storage"`` — the record frame carries a storage-delta reason at
      the known context offset (intrinsic), OR a small companion frame nearby
      carries the raw item id (windowed reference). The item is entering
      storage; covers player inventory->storage moves AND worker deposits.
    - ``None`` — no feature fires, or the two intrinsic features contradict.

    Two INTRINSIC features (both in-frame, both validated across two opcode
    generations; see docs/PACKET_PROTOCOL_WIKI.md) decide direction and take
    priority: the high-entropy context label => into_inventory, the
    storage-delta context => into_storage. If both fire the frame is refused
    (``None``), never guessed. The WINDOWED reference frame is only a fallback
    for into_storage when no intrinsic feature fired (e.g. the legacy
    generation, whose storage delta has no offset-8 context) — it can bleed in
    from an adjacent transaction, so an intrinsic signal always outranks it.
    """
    frame_index = _frame_index or _FrameIndex(frames)
    reference_frame = _has_item_reference_frame(
        frame_index, record_frame, item_id, context_frames
    )
    context_label = _has_context_label_before(record_frame, item_offset)
    storage_context = _has_storage_delta_context(record_frame, item_offset)

    if context_label and storage_context:
        family: Optional[str] = None  # contradictory intrinsic signals: refuse
    elif context_label:
        family = "into_inventory"
    elif storage_context:
        family = "into_storage"
    elif reference_frame:
        family = "into_storage"
    else:
        family = None
    return family, reference_frame, context_label, storage_context


def _select_records_by_family(
    frames: list[BDOFrame],
    records: list["_CalibratedItemRecord"],
    action: str,
    context_frames: int,
    evidence: list[DirectionEvidence],
    strict: bool,
    frame_index: _FrameIndex,
    allow_unclassified: bool = False,
) -> list["_CalibratedItemRecord"]:
    """Keep only records whose detected family matches ``action``.

    Records the classification of every candidate in ``evidence``. In strict
    (explicit single-direction) mode, a candidate that clearly belongs to the
    opposite family with none matching raises :class:`DirectionMismatchError`.

    ``allow_unclassified`` keeps records neither feature can classify. It is
    set only for explicit inventory-to-storage calibration: an explicit
    declaration must stay usable even if a future patch silences both
    features (the post-patch recovery path), so strictness there means
    "refuse contradiction", not "require positive proof". Auto mode never
    allows unclassified records — with no declaration to fall back on, an
    unclassifiable record is dropped.
    """
    expected = _EXPECTED_FAMILY[action]
    matched: list[_CalibratedItemRecord] = []
    opposite: Optional[str] = None
    contradictory_intrinsics = False
    for record in records:
        family, reference_frame, context_label, storage_context = detect_transfer_family(
            frames,
            record.frame,
            record.item_offset,
            record.item_id,
            context_frames,
            _frame_index=frame_index,
        )
        evidence.append(
            DirectionEvidence(
                action=action,
                opcode=record.frame.opcode,
                detected_family=family,
                reference_frame=reference_frame,
                context_label=context_label,
                storage_context=storage_context,
            )
        )
        contradictory = family is None and context_label and storage_context
        contradictory_intrinsics = contradictory_intrinsics or contradictory
        genuinely_unclassified = (
            family is None
            and not context_label
            and not storage_context
            and not reference_frame
        )
        if family == expected or (
            allow_unclassified and genuinely_unclassified
        ):
            matched.append(record)
        elif family is not None:
            opposite = family

    if not matched and contradictory_intrinsics and strict:
        raise DirectionMismatchError(
            f"declared action {action!r} but the capture contains a candidate "
            "with contradictory intrinsic direction signals; refusing to guess"
        )
    if not matched and opposite is not None and strict:
        observed = (
            "storage-to-inventory"
            if opposite == "into_inventory"
            else "inventory-to-storage"
        )
        raise DirectionMismatchError(
            f"declared action {action!r} but the capture's structure indicates "
            f"{observed!r} (item entering "
            f"{'inventory' if opposite == 'into_inventory' else 'storage'}). "
            "Perform the declared action, or use auto calibration."
        )
    return matched


def _calibrate_loot_preview(
    frames: list[BDOFrame],
    options: _Options,
    ignored: list[str],
) -> list[MessageSpec]:
    records = _find_calibration_item_records(frames, options, "loot-preview", ignored)
    preview_records = [
        record
        for record in records
        if record.instance == LOOT_PREVIEW_SENTINEL_INSTANCE
        and _passes_min_confidence(record.confidence, options.min_confidence)
    ]
    if not preview_records:
        return []

    best = max(preview_records, key=lambda record: record.confidence)
    return [
        MessageSpec(
            event="LOOT_PREVIEW",
            opcode=best.frame.opcode,
            length=best.frame.length,
            item_id_offset=best.item_offset,
            quantity_offset=best.item_offset + 4,
            item_instance_offset=best.instance_offset,
            confidence=_confidence_label(best.confidence),
            source=_calibration_source(options, "loot-preview"),
            observed_at=_iso_timestamp(best.frame.context.timestamp),
            score=best.confidence,
        )
    ]


def _calibrate_storage_to_inventory(
    frames: list[BDOFrame],
    options: _Options,
    ignored: list[str],
    evidence: list[DirectionEvidence],
    strict: bool,
) -> list[MessageSpec]:
    records = _find_calibration_item_records(
        frames,
        options,
        "storage-to-inventory",
        ignored,
    )
    receipt_records = [
        record
        for record in records
        if record.instance is not None
        and record.instance != LOOT_PREVIEW_SENTINEL_INSTANCE
        and _passes_min_confidence(record.confidence, options.min_confidence)
    ]
    # Family selection subsumes the legacy "known context label before the
    # record" receipt filter (into_inventory fires on exactly that label), and
    # running it on ALL structural candidates makes strict mismatch detection
    # symmetric: a wrong-direction capture raises here with evidence recorded
    # instead of silently pre-filtering down to an empty result.
    frame_index = options.frame_index or _FrameIndex(frames)
    receipt_records = _select_records_by_family(
        frames,
        receipt_records,
        "storage-to-inventory",
        options.context_frames,
        evidence,
        strict,
        frame_index,
    )
    if not receipt_records:
        return []

    # On ties (a multi-record frame yields one candidate per record, all with
    # equal confidence) prefer the FIRST record: spec offsets are relative to
    # the first record and later ones are reached via repeat_stride.
    best = max(
        receipt_records, key=lambda record: (record.confidence, -record.item_offset)
    )
    source_decrement = _discover_source_container_decrement(frames, best, options)
    if source_decrement is None:
        ignored.append(
            f'NOTE opcode=0x{best.frame.opcode:04X} '
            f'length={best.frame.length} item_offset={best.item_offset} '
            'reason="source-decrement-not-found;promoting-receipt-only"'
        )

    # Write the SINGLE-record length even when calibrated from a multi-record
    # frame (unstackables): the recorded length acts as a minimum at load
    # time, so the observed multi-record length would block single transfers.
    layout_item_offset, layout_instance_offset = _first_transfer_record_layout(
        best.frame,
        best.item_offset,
        best.instance_offset,
    )
    single_record_length, observed_stride = _record_frame_shape(
        best.frame,
        best.item_id,
        layout_item_offset,
        layout_instance_offset,
    )
    specs = [
        MessageSpec(
            event="INVENTORY_TRANSFER",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=layout_item_offset,
            quantity_offset=layout_item_offset + 4,
            item_instance_offset=layout_instance_offset,
            context_offset=_discover_context_offset(best.frame, layout_item_offset),
            repeat_stride=observed_stride,
            confidence=_confidence_label(best.confidence),
            source=_calibration_source(options, "storage-to-inventory"),
            observed_at=_iso_timestamp(best.frame.context.timestamp),
            score=best.confidence,
        )
    ]

    if source_decrement is not None:
        specs.append(source_decrement)
    return specs


def _calibrate_inventory_to_storage(
    frames: list[BDOFrame],
    options: _Options,
    ignored: list[str],
    evidence: list[DirectionEvidence],
    strict: bool,
) -> list[MessageSpec]:
    records = _find_calibration_item_records(
        frames,
        options,
        "inventory-to-storage",
        ignored,
    )
    storage_records = [
        record
        for record in records
        if record.instance is not None
        and record.instance != LOOT_PREVIEW_SENTINEL_INSTANCE
        and _passes_min_confidence(record.confidence, options.min_confidence)
    ]
    frame_index = options.frame_index or _FrameIndex(frames)
    storage_records = _select_records_by_family(
        frames,
        storage_records,
        "inventory-to-storage",
        options.context_frames,
        evidence,
        strict,
        frame_index,
        allow_unclassified=strict,
    )
    if not storage_records:
        return []

    # Same first-record tie-break as the receipt path (multi-record frames).
    best = max(
        storage_records, key=lambda record: (record.confidence, -record.item_offset)
    )
    specs: list[MessageSpec] = []
    # The single-record wrapper normally wins the primary-record score because
    # its normalized message length is directly observable.  Do not let that
    # choice discard stronger repeated decrement evidence from another
    # validated deposit in the same calibration run.  Evaluate record zero of
    # every unique target deposit frame; repeated shapes already outrank their
    # single-record counterparts in companion scoring, while incompatible
    # equal-strength shapes still fail closed in the shared selector.
    first_storage_records: dict[int, _CalibratedItemRecord] = {}
    for record in storage_records:
        frame_identity = id(record.frame)
        previous = first_storage_records.get(frame_identity)
        if previous is None or record.item_offset < previous.item_offset:
            first_storage_records[frame_identity] = record
    source_stack_candidates: list[MessageSpec] = []
    for record in first_storage_records.values():
        candidate = _discover_source_stack_decrement(frames, record, options)
        if candidate is not None:
            source_stack_candidates.append(candidate)
    source_stack = _unique_best_companion_spec(source_stack_candidates)
    if source_stack is not None:
        specs.append(source_stack)

    source_ref = _discover_source_item_reference(frames, best, options)
    if source_ref is not None:
        specs.append(source_ref)

    # Same single-record length normalization as the receipt spec; also record
    # the observed stride so a multi-record storage delta (unstackable
    # deposits) decodes all records under the written profile.
    layout_item_offset, layout_instance_offset = _first_transfer_record_layout(
        best.frame,
        best.item_offset,
        best.instance_offset,
    )
    single_record_length, observed_stride = _record_frame_shape(
        best.frame,
        best.item_id,
        layout_item_offset,
        layout_instance_offset,
    )
    storage_context_offset = _discover_storage_context_offset_from_frames(
        (record.frame for record in storage_records),
        opcode=best.frame.opcode,
        item_offset=layout_item_offset,
    )
    record_count_offset = _discover_storage_record_count_offset(
        frames,
        records=storage_records,
        opcode=best.frame.opcode,
        item_offset=layout_item_offset,
        instance_offset=layout_instance_offset,
        single_record_length=single_record_length,
    )
    # The strongest target record can be the single-record action even when
    # the same guided run also contains the multi-record shape that proves the
    # wrapper stride. Learn that stride across every structurally compatible
    # same-opcode frame instead of coupling it to whichever record won the score
    # tie. This lets character-state analysis validate count-zero envelopes
    # even for an account whose storages are all empty after calibration.
    observed_strides = {observed_stride} if observed_stride is not None else set()
    seen_shape_messages: set[bytes] = set()
    for frame in frames:
        if frame.opcode != best.frame.opcode or frame.message in seen_shape_messages:
            continue
        seen_shape_messages.add(frame.message)
        candidate_base, candidate_stride = _record_frame_shape(
            frame,
            best.item_id,
            layout_item_offset,
            layout_instance_offset,
        )
        if candidate_base == single_record_length and candidate_stride is not None:
            observed_strides.add(candidate_stride)
    repeat_stride = (
        next(iter(observed_strides)) if len(observed_strides) == 1 else None
    )
    missing_authority: list[str] = []
    if storage_context_offset is None:
        missing_authority.append("destination-field")
    if record_count_offset is None:
        missing_authority.append("record-count-field")
    if missing_authority:
        missing_text = ", ".join(missing_authority)
        guidance: list[str] = []
        if "destination-field" in missing_authority:
            guidance.append(
                "repeat the deposit in an unambiguous registered town such as "
                "Velia or Heidel (or include controlled deposits to different towns)"
            )
        if "record-count-field" in missing_authority:
            guidance.append(
                "include two independently validated record counts (for example "
                "one single-record and one unstackable multi-record deposit, or "
                "two unstackable deposits with different counts)"
            )
        raise CalibrationAuthorityError(
            f"storage opcode 0x{best.frame.opcode:04X} was observed, but its "
            f"{missing_text} could not be uniquely proven. No calibration "
            "result was produced and no profile should be updated. To resolve "
            f"this, {'; and '.join(guidance)}. Then retry calibration."
        )
    specs.append(
        MessageSpec(
            event="STORAGE_ITEM_DELTA",
            opcode=best.frame.opcode,
            length=single_record_length,
            item_id_offset=layout_item_offset,
            quantity_added_offset=layout_item_offset + 4,
            destination_instance_offset=layout_instance_offset,
            context_offset=storage_context_offset,
            record_count_offset=record_count_offset,
            repeat_stride=repeat_stride,
            confidence=_confidence_label(best.confidence),
            source=_calibration_source(options, "inventory-to-storage"),
            observed_at=_iso_timestamp(best.frame.context.timestamp),
            score=best.confidence,
        )
    )
    return specs
