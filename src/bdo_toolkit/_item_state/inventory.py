"""Inventory record metadata and hydration-generation selection."""

from __future__ import annotations

from typing import Iterable, Optional

from .._record_geometry import infer_repeat_stride
from .._protocol import (
    BDOFrame,
    CHARACTER_LOAD_CONTEXT,
    EventSpec,
)
from ..events import BDOEvent

from ._constants import (
    _INVENTORY_CONTAINER_LABELS,
    _INVENTORY_GENERATION_GAP_SECONDS,
    _INVENTORY_TRAILING_DISCOVERY_BYTES,
)
from ._records import (
    _FrameKey,
    _HydrationAnchor,
    _InventoryAssembly,
    _InventoryGeneration,
    _InventoryRecordMetadata,
    _anchor_flow_generation_key,
    _event_flow_generation_key,
    _event_frame_key,
    _frame_key,
    _snapshot_item,
    _spec_candidates_by_opcode,
)
from .models import (
    InventoryHydrationDiagnostics,
    InventorySnapshotSummary,
    SnapshotItem,
)


def _inventory_frame_stride(
    frame: BDOFrame,
    spec: EventSpec,
    group: list[BDOEvent],
) -> Optional[int]:
    """Derive and validate one frame's repeated-record geometry."""
    count = len(group)
    base_length = spec.single_record_message_length
    if count < 2 or base_length is None:
        return None
    stride = infer_repeat_stride(frame.length, base_length, count)
    if stride is None:
        return None
    if stride <= _INVENTORY_TRAILING_DISCOVERY_BYTES:
        return None
    if frame.length != base_length + (count - 1) * stride:
        return None
    if len(frame.message) < frame.length:
        return None
    if not _inventory_event_geometry_valid(spec, group, stride):
        return None
    return stride


def _unique_inventory_multi_layout(
    frame: BDOFrame,
    group: list[BDOEvent],
    candidates: Iterable[EventSpec],
) -> Optional[tuple[EventSpec, int]]:
    matches: list[tuple[EventSpec, int]] = []
    for spec in candidates:
        if not _frame_has_zero_context(frame, spec):
            continue
        stride = _inventory_frame_stride(frame, spec, group)
        if stride is not None:
            matches.append((spec, stride))
    return matches[0] if len(matches) == 1 else None


def _unique_inventory_single_layout(
    frame: BDOFrame,
    group: list[BDOEvent],
    candidates: Iterable[EventSpec],
    sibling_strides: dict[EventSpec, set[int]],
) -> Optional[tuple[EventSpec, int]]:
    matches: list[tuple[EventSpec, int]] = []
    for spec in candidates:
        proven = sibling_strides.get(spec, set())
        if len(proven) != 1:
            continue
        stride = next(iter(proven))
        if (
            not _frame_has_zero_context(frame, spec)
            or spec.single_record_message_length != frame.length
            or not _inventory_event_geometry_valid(spec, group, stride)
        ):
            continue
        matches.append((spec, stride))
    return matches[0] if len(matches) == 1 else None


def _inventory_event_geometry_valid(
    spec: EventSpec,
    group: list[BDOEvent],
    stride: int,
) -> bool:
    """Require a complete, ordered record set for a candidate stride."""
    count = len(group)
    if count == 0:
        return False
    ordered = sorted(
        group,
        key=lambda event: (
            event.record_offset if event.record_offset is not None else -1
        ),
    )
    offsets = [event.record_offset for event in ordered]
    if any(offset is None for offset in offsets):
        return False
    if offsets != [spec.item_offset + index * stride for index in range(count)]:
        return False
    if any(
        event.record_count is not None and event.record_count != count
        for event in ordered
    ):
        return False
    indexes = [event.record_index for event in ordered]
    if any(index is not None for index in indexes):
        if indexes != list(range(1, count + 1)):
            return False
    return True


def _discover_inventory_tail_layout(
    frame_groups: list[tuple[BDOFrame, list[BDOEvent], EventSpec, int]],
) -> Optional[tuple[int, int]]:
    """Jointly discover slot/container columns near the repeated-record tail.

    The layout is accepted only when exactly one pair explains every complete
    multi-record group. Requiring at least two distinct known container codes
    rejects padding columns that happen to contain only zeroes.
    """
    if len(frame_groups) < 2:
        return None
    common_stride = {stride for _, _, _, stride in frame_groups}
    if len(common_stride) != 1:
        return None
    stride = next(iter(common_stride))
    window_start = max(0, stride - _INVENTORY_TRAILING_DISCOVERY_BYTES)
    candidates: list[tuple[int, int]] = []

    for slot_relative in range(window_start, stride):
        slot_groups: list[list[int]] = []
        for frame, group, _, _ in frame_groups:
            ordered = sorted(group, key=lambda event: int(event.record_offset or 0))
            slots = [
                frame.message[int(event.record_offset) + slot_relative]
                for event in ordered
                if event.record_offset is not None
                and int(event.record_offset) + slot_relative < len(frame.message)
            ]
            slot_groups.append(slots)
        if any(
            len(slots) != len(group)
            for slots, (_, group, _, _) in zip(slot_groups, frame_groups)
        ):
            continue
        if any(
            not slots
            or any(slot == 0xFF for slot in slots)
            or slots != sorted(slots)
            or len(set(slots)) != len(slots)
            for slots in slot_groups
        ):
            continue

        # Observed generations serialize these neighboring fields in both
        # orders. Keep the bounded tail search, but do not treat their order as
        # part of the protocol invariant.
        for container_relative in range(
            max(window_start, slot_relative - 4),
            min(stride, slot_relative + 5),
        ):
            if container_relative == slot_relative:
                continue
            observed_codes: set[int] = set()
            valid = True
            for frame, group, _, _ in frame_groups:
                codes = {
                    frame.message[int(event.record_offset) + container_relative]
                    for event in group
                    if event.record_offset is not None
                    and int(event.record_offset) + container_relative
                    < len(frame.message)
                }
                if len(codes) != 1:
                    valid = False
                    break
                code = next(iter(codes))
                if code not in _INVENTORY_CONTAINER_LABELS:
                    valid = False
                    break
                observed_codes.add(code)
            if valid and len(observed_codes) >= 2:
                candidates.append((slot_relative, container_relative))

    if len(candidates) != 1:
        return None
    return candidates[0]


def _discover_inventory_header_container_offset(
    frame_groups: list[tuple[BDOFrame, list[BDOEvent], EventSpec, int]],
) -> Optional[int]:
    """Discover a wrapper-level container byte shared by every sibling record.

    The August wrapper moved the known 00/10/18/0B container identity out of
    each repeated-record tail and into the prefix immediately before item one.
    Search the framed prefix instead of pinning that new position, and accept
    it only when one unique byte column explains at least two container groups.
    """
    if len(frame_groups) < 2:
        return None
    search_end = min(spec.item_offset for _, _, spec, _ in frame_groups)
    candidates: list[int] = []
    for offset in range(5, search_end):
        codes = []
        for frame, _, _, _ in frame_groups:
            if offset >= len(frame.message):
                break
            code = frame.message[offset]
            if code not in _INVENTORY_CONTAINER_LABELS:
                break
            codes.append(code)
        else:
            if len(set(codes)) >= 2:
                candidates.append(offset)
    return candidates[0] if len(candidates) == 1 else None


def _inventory_header_metadata(
    frame: BDOFrame,
    group: list[BDOEvent],
    container_offset: int,
) -> Optional[dict[int, _InventoryRecordMetadata]]:
    if container_offset >= len(frame.message):
        return None
    code = frame.message[container_offset]
    if code not in _INVENTORY_CONTAINER_LABELS:
        return None
    return {
        event.record_offset: _InventoryRecordMetadata(None, code)
        for event in group
        if event.record_offset is not None
    }


def _inventory_record_metadata(
    frame: BDOFrame,
    group: list[BDOEvent],
    spec: EventSpec,
    stride: int,
    layout: tuple[int, int],
) -> Optional[dict[int, _InventoryRecordMetadata]]:
    """Extract one validated frame's dynamically discovered tail fields."""
    base_length = spec.single_record_message_length
    if base_length is None:
        return None
    count = len(group)
    expected_length = base_length if count == 1 else base_length + (count - 1) * stride
    if frame.length != expected_length or len(frame.message) < frame.length:
        return None
    if not _inventory_event_geometry_valid(spec, group, stride):
        return None

    slot_relative, container_relative = layout
    extracted: dict[int, _InventoryRecordMetadata] = {}
    slots: list[int] = []
    codes: set[int] = set()
    for event in sorted(group, key=lambda candidate: int(candidate.record_offset or 0)):
        assert event.record_offset is not None
        slot_offset = event.record_offset + slot_relative
        container_offset = event.record_offset + container_relative
        if max(slot_offset, container_offset) >= len(frame.message):
            return None
        slot = frame.message[slot_offset]
        code = frame.message[container_offset]
        if slot == 0xFF or code not in _INVENTORY_CONTAINER_LABELS:
            return None
        slots.append(slot)
        codes.add(code)
        extracted[event.record_offset] = _InventoryRecordMetadata(slot, code)

    if slots != sorted(slots) or len(slots) != len(set(slots)) or len(codes) != 1:
        return None
    return extracted


def _frame_has_zero_context(frame: BDOFrame, spec: EventSpec) -> bool:
    if spec.source_context_offset is None:
        return False
    start = spec.source_context_offset
    end = start + spec.source_context_length
    return (
        end <= len(frame.message) and frame.message[start:end] == CHARACTER_LOAD_CONTEXT
    )


def _latest_inventory_generation(
    frames: tuple[BDOFrame, ...],
    events: tuple[BDOEvent, ...],
    specs: Iterable[EventSpec],
) -> _InventoryGeneration:
    """Select the latest inventory burst, including proven count-zero wrappers."""
    specs_by_opcode = _spec_candidates_by_opcode(specs)
    observations = {
        _HydrationAnchor(event.timestamp, _event_frame_key(event)) for event in events
    }
    event_frame_keys = {_event_frame_key(event) for event in events}
    for frame in frames:
        frame_key = _frame_key(frame)
        if frame_key in event_frame_keys:
            continue
        empty_matches = [
            spec
            for spec in specs_by_opcode.get(frame.opcode, ())
            if spec.single_record_message_length is not None
            and spec.repeat_stride is not None
            and spec.repeat_stride > 0
            and spec.single_record_message_length > spec.repeat_stride
            and frame.length == spec.single_record_message_length - spec.repeat_stride
            and _frame_has_zero_context(frame, spec)
        ]
        if len(empty_matches) == 1:
            observations.add(_HydrationAnchor(frame.context.timestamp, frame_key))

    if not observations:
        return _InventoryGeneration(
            events=events,
            anchors=(),
            start=None,
            flow_generation_key=None,
            generations_observed=0,
        )

    ordered = sorted(
        observations,
        key=lambda item: (
            item.timestamp,
            item.frame_key.source_ip,
            item.frame_key.source_port,
            item.frame_key.destination_ip,
            item.frame_key.destination_port,
            item.frame_key.flow_generation,
            item.frame_key.stream_sequence is None,
            item.frame_key.stream_sequence or 0,
        ),
    )
    first = ordered[0]
    previous_generation_key = _anchor_flow_generation_key(first)
    generation_starts = [first.timestamp]
    generation_keys = [previous_generation_key]
    previous_timestamp = first.timestamp
    for observation in ordered[1:]:
        timestamp = observation.timestamp
        generation_key = _anchor_flow_generation_key(observation)
        if (
            timestamp - previous_timestamp > _INVENTORY_GENERATION_GAP_SECONDS
            or generation_key != previous_generation_key
        ):
            generation_starts.append(timestamp)
            generation_keys.append(generation_key)
        previous_timestamp = timestamp
        previous_generation_key = generation_key

    latest_start = generation_starts[-1]
    latest_key = generation_keys[-1]
    return _InventoryGeneration(
        events=tuple(
            event
            for event in events
            if event.timestamp >= latest_start
            and _event_flow_generation_key(event) == latest_key
        ),
        anchors=tuple(
            observation
            for observation in ordered
            if observation.timestamp >= latest_start
            and _anchor_flow_generation_key(observation) == latest_key
        ),
        start=latest_start,
        flow_generation_key=latest_key,
        generations_observed=len(generation_starts),
    )


def _assemble_inventory(
    specs: tuple[EventSpec, ...],
    frames: tuple[BDOFrame, ...],
    events: tuple[BDOEvent, ...],
    *,
    generations_observed: int,
) -> _InventoryAssembly:
    groups: dict[_FrameKey, list[BDOEvent]] = {}
    for event in events:
        groups.setdefault(_event_frame_key(event), []).append(event)

    frames_by_key = {_frame_key(frame): frame for frame in frames}
    specs_by_opcode = _spec_candidates_by_opcode(specs)
    multi_groups_by_spec: dict[
        EventSpec, list[tuple[BDOFrame, list[BDOEvent], EventSpec, int]]
    ] = {}
    strides_by_key: dict[_FrameKey, int] = {}
    selected_specs_by_key: dict[_FrameKey, EventSpec] = {}
    sibling_strides: dict[EventSpec, set[int]] = {}
    prefix_candidates: dict[EventSpec, set[int]] = {}

    # A multi-record frame proves its own stride from L, B, and N. Layout
    # discovery is intentionally separate: stride alone does not prove
    # where slot/container metadata moved in a new protocol generation.
    for key, group in groups.items():
        frame = frames_by_key.get(key)
        if frame is None:
            continue
        selected = _unique_inventory_multi_layout(
            frame,
            group,
            specs_by_opcode.get(frame.opcode, ()),
        )
        if selected is None:
            continue
        spec, stride = selected
        strides_by_key[key] = stride
        selected_specs_by_key[key] = spec
        sibling_strides.setdefault(spec, set()).add(stride)
        prefix_candidates.setdefault(spec, set()).add(
            frame.length - len(group) * stride
        )
        multi_groups_by_spec.setdefault(spec, []).append(
            (frame, group, spec, stride)
        )

    tail_layouts = {
        spec: _discover_inventory_tail_layout(frame_groups)
        for spec, frame_groups in multi_groups_by_spec.items()
    }
    header_container_offsets = {
        spec: _discover_inventory_header_container_offset(frame_groups)
        for spec, frame_groups in multi_groups_by_spec.items()
        if tail_layouts.get(spec) is None
    }

    # A calibrated single-record base and repeat stride also prove the
    # zero-record prefix. This preserves empty inventory hydration as an
    # observed state even when the capture contains no occupied records.
    for candidates in specs_by_opcode.values():
        for spec in candidates:
            if (
                spec.single_record_message_length is not None
                and spec.repeat_stride is not None
                and spec.repeat_stride > 0
                and spec.single_record_message_length > spec.repeat_stride
            ):
                prefix_candidates.setdefault(spec, set()).add(
                    spec.single_record_message_length - spec.repeat_stride
                )
    metadata_by_record: dict[tuple[_FrameKey, int], _InventoryRecordMetadata] = {}
    for key, group in groups.items():
        frame = frames_by_key.get(key)
        if frame is None:
            continue
        spec_for_group = selected_specs_by_key.get(key)
        stride_for_group = strides_by_key.get(key)
        if stride_for_group is None and len(group) == 1:
            selected = _unique_inventory_single_layout(
                frame,
                group,
                specs_by_opcode.get(frame.opcode, ()),
                sibling_strides,
            )
            if selected is not None:
                spec_for_group, stride_for_group = selected
                selected_specs_by_key[key] = spec_for_group
                strides_by_key[key] = stride_for_group
        if spec_for_group is None or stride_for_group is None:
            continue
        tail_layout = tail_layouts.get(spec_for_group)
        if tail_layout is not None:
            extracted = _inventory_record_metadata(
                frame,
                group,
                spec_for_group,
                stride_for_group,
                tail_layout,
            )
        else:
            header_offset = header_container_offsets.get(spec_for_group)
            if header_offset is None:
                continue
            extracted = _inventory_header_metadata(
                frame,
                group,
                header_offset,
            )
        if extracted is None:
            continue
        metadata_by_record.update(
            {
                (key, record_offset): metadata
                for record_offset, metadata in extracted.items()
            }
        )

    latest: dict[str, SnapshotItem] = {}
    missing_instance = 0
    for event in events:
        if event.item_instance is None:
            missing_instance += 1
            continue
        instance = event.item_instance
        metadata = (
            metadata_by_record.get((_event_frame_key(event), event.record_offset))
            if event.record_offset is not None
            else None
        )
        latest[instance] = _snapshot_item(event, instance, metadata)

    prefixes = {
        spec: next(iter(candidates))
        for spec, candidates in prefix_candidates.items()
        if len(candidates) == 1
    }

    frame_counts: list[int] = []
    counted_keys: set[_FrameKey] = set()
    for frame in frames:
        key = _frame_key(frame)
        frame_group = groups.get(key)
        if frame_group is not None and key in selected_specs_by_key:
            frame_counts.append(len(frame_group))
            counted_keys.add(key)
            continue
        empty_matches = [
            candidate
            for candidate in specs_by_opcode.get(frame.opcode, ())
            if _frame_has_zero_context(frame, candidate)
            and prefixes.get(candidate) == frame.length
        ]
        if frame_group is None and len(empty_matches) == 1:
            frame_counts.append(0)
            counted_keys.add(key)

    # Events can still be useful when a caller feeds normalized records
    # without generic frame observations.
    for key, group in groups.items():
        if key not in counted_keys:
            frame_counts.append(len(group))

    identified_records = len(events) - missing_instance
    duplicate_records = identified_records - len(latest)

    latest_records = tuple(sorted(latest.values(), key=lambda item: item.instance))
    items = tuple(item for item in latest_records if not item.is_currency_balance)
    currency_balances = tuple(
        item for item in latest_records if item.is_currency_balance
    )
    source_opcodes = {
        frame.opcode
        for frame in frames
        if _frame_key(frame) in counted_keys
    }
    message_lengths = {
        frame.length
        for frame in frames
        if _frame_key(frame) in counted_keys
    }
    source_opcodes.update(
        event.opcode for event in events if event.opcode is not None
    )
    message_lengths.update(
        event.message_length
        for event in events
        if isinstance(event.message_length, int)
        and not isinstance(event.message_length, bool)
    )
    return _InventoryAssembly(
        summary=InventorySnapshotSummary(
            hydration_observed=bool(frame_counts),
            items=items,
            currency_balances=currency_balances,
        ),
        missing_instance_records=missing_instance,
        diagnostics=InventoryHydrationDiagnostics(
            raw_records=len(events),
            duplicate_records=duplicate_records,
            group_counts=tuple(frame_counts),
            inferred_strides=tuple(
                sorted(
                    {
                        stride
                        for strides in sibling_strides.values()
                        for stride in strides
                    }
                )
            ),
            generations_observed=generations_observed,
            source_opcodes=tuple(sorted(source_opcodes)),
            message_lengths=tuple(sorted(message_lengths)),
        ),
    )
