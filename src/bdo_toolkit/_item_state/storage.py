"""Storage hydration reconciliation, sweep selection, and empty envelopes."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Optional

from .._protocol import (
    BDOFrame,
    EventSpec,
    STORAGE_LOCATIONS,
    storage_location,
)
from ..events import BDOEvent

from ._constants import (
    _STORAGE_DESTINATION_CHUNK_GAP_SECONDS,
    _STORAGE_EMPTY_WINDOW_MARGIN_SECONDS,
    _STORAGE_HYDRATION_BURST_GAP_SECONDS,
    _STORAGE_HYDRATION_EPOCH_SECONDS,
    _STORAGE_HYDRATION_MAX_BURST_SECONDS,
    _STORAGE_HYDRATION_MIN_DESTINATIONS,
)
from ._records import (
    _FrameKey,
    _HydrationAnchor,
    _StorageAssembly,
    _StorageDestinationBlock,
    _StorageEmptySchema,
    _StorageGroupObservation,
    _anchor_flow_generation_key,
    _event_flow_generation_key,
    _event_frame_key,
    _frame_key,
    _snapshot_item,
    _spec_candidates_by_opcode,
)
from .models import (
    SnapshotItem,
    StorageDestinationDiagnostics,
    StorageSnapshotSummary,
)


def _character_storage_snapshot_fallback(
    frames: Iterable[BDOFrame],
    neutral_events: Iterable[BDOEvent],
    hydration_anchors: Iterable[_HydrationAnchor],
    specs: Iterable[EventSpec],
) -> tuple[tuple[BDOEvent, ...], tuple[_StorageGroupObservation, ...]]:
    """Prove a sparse storage hydration cohort inside the dedicated API.

    The general live classifier intentionally requires eight *populated*
    destinations so an uncorrelated worker batch cannot become a snapshot.
    Character-load capture additionally retains exact count-zero envelopes.
    Those envelopes can prove the same broad, tightly timed town sweep for an
    account with only a few populated storages without weakening live event
    filtering for every application.
    """

    frames = tuple(frames)
    neutral_events = tuple(neutral_events)
    hydration_anchors = tuple(hydration_anchors)
    if not hydration_anchors:
        return (), ()

    anchors: dict[tuple[str, int, str, int, int], float] = {}
    for hydration_anchor in hydration_anchors:
        key = _anchor_flow_generation_key(hydration_anchor)
        anchors[key] = max(
            anchors.get(key, hydration_anchor.timestamp),
            hydration_anchor.timestamp,
        )

    observations = _storage_group_observations(
        frames,
        neutral_events,
        specs,
        hydration_anchors=hydration_anchors,
    )
    by_stream: dict[
        tuple[str, int, str, int, int, int],
        list[_StorageGroupObservation],
    ] = {}
    for observation in observations:
        frame_key = observation.frame_key
        stream_key = (
            frame_key.source_ip,
            frame_key.source_port,
            frame_key.destination_ip,
            frame_key.destination_port,
            frame_key.flow_generation,
            observation.opcode,
        )
        by_stream.setdefault(stream_key, []).append(observation)

    candidates: list[tuple[_StorageGroupObservation, ...]] = []
    for stream_key, stream_observations in by_stream.items():
        anchor = anchors.get(stream_key[:5])
        if anchor is None:
            continue
        ordered = sorted(
            stream_observations,
            key=lambda observation: observation.timestamp,
        )
        burst: list[_StorageGroupObservation] = []

        def consider() -> None:
            if not burst:
                return
            distinct_destinations = {
                observation.storage_id
                for observation in burst
                if observation.storage_id > 0
            }
            if (
                len(distinct_destinations) >= _STORAGE_HYDRATION_MIN_DESTINATIONS
                and any(observation.empty for observation in burst)
                and anchor <= burst[0].timestamp
                and burst[-1].timestamp - anchor
                <= _STORAGE_HYDRATION_EPOCH_SECONDS
            ):
                candidates.append(tuple(burst))

        for observation in ordered:
            if burst and (
                observation.timestamp - burst[-1].timestamp
                > _STORAGE_HYDRATION_BURST_GAP_SECONDS
                or observation.timestamp - burst[0].timestamp
                > _STORAGE_HYDRATION_MAX_BURST_SECONDS
            ):
                consider()
                burst = []
            burst.append(observation)
        consider()

    if not candidates:
        return (), ()
    selected = max(candidates, key=lambda cohort: cohort[-1].timestamp)
    selected_records = {
        (observation.frame_key, observation.timestamp, observation.storage_id)
        for observation in selected
        if not observation.empty
    }
    promoted: list[BDOEvent] = []
    for event in neutral_events:
        if (
            _event_frame_key(event),
            event.timestamp,
            event.storage_id,
        ) not in selected_records:
            continue
        promoted.append(
            replace(
                event,
                event_type="storage_snapshot",
                source=None,
            )
        )
    return tuple(promoted), selected


def _reconcile_split_storage_hydration(
    frames: Iterable[BDOFrame],
    snapshot_events: Iterable[BDOEvent],
    neutral_events: Iterable[BDOEvent],
    live_boundaries: Iterable[BDOEvent],
    hydration_anchors: Iterable[_HydrationAnchor],
    specs: Iterable[EventSpec],
) -> tuple[
    tuple[BDOEvent, ...],
    tuple[_StorageGroupObservation, ...],
    int,
]:
    """Extend a proven snapshot sweep across harmless timing-burst splits.

    The continuous live classifier deliberately treats a timing gap as a
    fail-neutral boundary.  The dedicated character-state API has stronger
    evidence: a selected inventory hydration generation plus storage records
    that were already promoted by the live classifier.  Neutral records may
    join such a proven sweep only on the same flow generation and opcode, in
    the bounded inventory epoch, and without crossing a positive live
    mutation.  Repeated destinations remain separate sweeps through
    :func:`_infer_storage_sweeps`.
    """

    frames = tuple(frames)
    snapshot_events = tuple(snapshot_events)
    neutral_events = tuple(neutral_events)
    live_boundaries = tuple(live_boundaries)
    hydration_anchors = tuple(hydration_anchors)
    specs = tuple(specs)
    if not snapshot_events or not neutral_events or not hydration_anchors:
        return snapshot_events, (), 0

    anchors: dict[tuple[str, int, str, int, int], float] = {}
    for hydration_anchor in hydration_anchors:
        key = _anchor_flow_generation_key(hydration_anchor)
        anchors[key] = max(
            anchors.get(key, hydration_anchor.timestamp),
            hydration_anchor.timestamp,
        )

    confirmed_groups = {
        (_event_frame_key(event), event.timestamp, event.storage_id)
        for event in snapshot_events
        if event.storage_id is not None
    }
    observations = _storage_group_observations(
        frames,
        (*snapshot_events, *neutral_events),
        specs,
        hydration_anchors=hydration_anchors,
    )

    boundaries_by_flow: dict[
        tuple[str, int, str, int, int],
        list[tuple[float, bool, int]],
    ] = {}
    for event in live_boundaries:
        frame_key = _event_frame_key(event)
        boundaries_by_flow.setdefault(
            _event_flow_generation_key(event),
            [],
        ).append(
            (
                event.timestamp,
                frame_key.stream_sequence is None,
                frame_key.stream_sequence or 0,
            )
        )
    for boundaries in boundaries_by_flow.values():
        boundaries.sort()

    cohorts: dict[
        tuple[str, int, str, int, int, int, int],
        list[_StorageGroupObservation],
    ] = {}
    for observation in observations:
        frame_key = observation.frame_key
        flow_key = (
            frame_key.source_ip,
            frame_key.source_port,
            frame_key.destination_ip,
            frame_key.destination_port,
            frame_key.flow_generation,
        )
        anchor = anchors.get(flow_key)
        if (
            anchor is None
            or observation.timestamp < anchor
            or observation.timestamp - anchor > _STORAGE_HYDRATION_EPOCH_SECONDS
        ):
            continue
        order_key = (
            observation.timestamp,
            frame_key.stream_sequence is None,
            frame_key.stream_sequence or 0,
        )
        boundary_index = sum(
            boundary <= order_key
            for boundary in boundaries_by_flow.get(flow_key, ())
        )
        cohorts.setdefault(
            (*flow_key, observation.opcode, boundary_index),
            [],
        ).append(observation)

    eligible_groups: set[tuple[_FrameKey, float, int]] = set()
    for cohort in cohorts.values():
        for sweep in _infer_storage_sweeps(cohort):
            sweep_groups = {
                (group.frame_key, group.timestamp, group.storage_id)
                for block in sweep
                for group in block.groups
                if not group.empty
            }
            if sweep_groups & confirmed_groups:
                eligible_groups.update(sweep_groups)

    promoted: list[BDOEvent] = []
    for event in neutral_events:
        group_key = (
            _event_frame_key(event),
            event.timestamp,
            event.storage_id,
        )
        if (
            event.storage_id is None
            or group_key in confirmed_groups
            or group_key not in eligible_groups
        ):
            continue
        promoted.append(
            replace(
                event,
                event_type="storage_snapshot",
                source=None,
            )
        )

    if not promoted:
        return snapshot_events, (), 0

    reconciled = tuple(
        sorted(
            (*snapshot_events, *promoted),
            key=lambda event: (
                event.timestamp,
                event.flow.source_ip,
                event.flow.source_port,
                event.flow.destination_ip,
                event.flow.destination_port,
                _event_frame_key(event).flow_generation,
                _event_frame_key(event).stream_sequence is None,
                _event_frame_key(event).stream_sequence or 0,
                event.record_index or 0,
            ),
        )
    )
    reconciled_observations = _storage_group_observations(
        frames,
        reconciled,
        specs,
        hydration_anchors=hydration_anchors,
    )
    return reconciled, reconciled_observations, len(promoted)


def _storage_group_observations(
    frames: Iterable[BDOFrame],
    events: Iterable[BDOEvent],
    specs: Iterable[EventSpec],
    *,
    hydration_anchors: Iterable[_HydrationAnchor] = (),
) -> tuple[_StorageGroupObservation, ...]:
    """Merge record-bearing frames and empty wrappers into capture order."""
    frames = tuple(frames)
    events = tuple(events)
    event_groups: dict[tuple[_FrameKey, float, int], list[BDOEvent]] = {}
    for event in events:
        if event.storage_id is None:
            continue
        event_groups.setdefault(
            (_event_frame_key(event), event.timestamp, event.storage_id),
            [],
        ).append(event)

    observations: list[_StorageGroupObservation] = []
    for (frame_key, timestamp, storage_id), group in event_groups.items():
        items_by_instance: dict[str, SnapshotItem] = {}
        missing_instance_records = 0
        for event in group:
            instance = event.storage_instance
            if instance is None:
                missing_instance_records += 1
                continue
            items_by_instance[instance] = _snapshot_item(event, instance)
        observations.append(
            _StorageGroupObservation(
                storage_id=storage_id,
                frame_key=frame_key,
                timestamp=timestamp,
                opcode=group[0].opcode or 0,
                message_length=group[0].message_length,
                items=tuple(
                    sorted(
                        items_by_instance.values(),
                        key=lambda item: item.instance,
                    )
                ),
                raw_records=len(group),
                missing_instance_records=missing_instance_records,
                empty=False,
            )
        )

    empty_schemas, hydration_windows = _storage_empty_schemas(
        events,
        specs,
        frames=frames,
        hydration_anchors=hydration_anchors,
    )
    for frame in frames:
        matches: list[int] = []
        for schema in empty_schemas.get(frame.opcode, ()):
            candidate_storage_id = _empty_storage_envelope_id(
                frame,
                schema,
                hydration_windows,
            )
            if candidate_storage_id is not None:
                matches.append(candidate_storage_id)
        if len(matches) != 1:
            continue
        storage_id = matches[0]
        observations.append(
            _StorageGroupObservation(
                storage_id=storage_id,
                frame_key=_frame_key(frame),
                timestamp=frame.context.timestamp,
                opcode=frame.opcode,
                message_length=frame.length,
                items=(),
                raw_records=0,
                missing_instance_records=0,
                empty=True,
            )
        )

    observations.sort(
        key=lambda observation: (
            observation.timestamp,
            observation.frame_key.source_ip,
            observation.frame_key.source_port,
            observation.frame_key.destination_ip,
            observation.frame_key.destination_port,
            observation.frame_key.flow_generation,
            observation.frame_key.stream_sequence is None,
            observation.frame_key.stream_sequence or 0,
            observation.opcode,
            observation.storage_id,
            observation.empty,
        )
    )
    return tuple(observations)


def _infer_storage_sweeps(
    observations: Iterable[_StorageGroupObservation],
) -> tuple[tuple[_StorageDestinationBlock, ...], ...]:
    """Conservatively split ordered destination blocks into repeated sweeps.

    Tightly timed consecutive nonempty groups for one destination are record
    chunks and stay together. A state change or a gap beyond the observed
    chunk window closes the block even when the destination is unchanged.
    Once a closed destination appears again, that repeat begins a new sweep.
    """
    blocks: list[_StorageDestinationBlock] = []
    current_storage_id: Optional[int] = None
    current_stream_key: Optional[tuple[str, int, str, int, int, int]] = None
    current_groups: list[_StorageGroupObservation] = []
    current_empty: Optional[bool] = None

    def close_current() -> None:
        nonlocal current_storage_id, current_stream_key, current_groups, current_empty
        if (
            current_storage_id is not None
            and current_stream_key is not None
            and current_groups
        ):
            blocks.append(
                _StorageDestinationBlock(
                    storage_id=current_storage_id,
                    stream_key=current_stream_key,
                    groups=tuple(current_groups),
                )
            )
        current_storage_id = None
        current_stream_key = None
        current_groups = []
        current_empty = None

    for observation in observations:
        observation_stream_key = (
            observation.frame_key.source_ip,
            observation.frame_key.source_port,
            observation.frame_key.destination_ip,
            observation.frame_key.destination_port,
            observation.frame_key.flow_generation,
            observation.opcode,
        )
        previous_timestamp = current_groups[-1].timestamp if current_groups else None
        if current_storage_id is not None and (
            observation.storage_id != current_storage_id
            or observation_stream_key != current_stream_key
            or observation.empty != current_empty
            or (
                previous_timestamp is not None
                and observation.timestamp - previous_timestamp
                > _STORAGE_DESTINATION_CHUNK_GAP_SECONDS
            )
        ):
            close_current()
        if current_storage_id is None:
            current_storage_id = observation.storage_id
            current_stream_key = observation_stream_key
            current_empty = observation.empty
        current_groups.append(observation)
    close_current()

    sweeps: list[tuple[_StorageDestinationBlock, ...]] = []
    current_sweep: list[_StorageDestinationBlock] = []
    destinations_seen: set[int] = set()
    current_sweep_stream: Optional[tuple[str, int, str, int, int, int]] = None
    for block in blocks:
        if current_sweep and (
            block.storage_id in destinations_seen
            or block.stream_key != current_sweep_stream
        ):
            sweeps.append(tuple(current_sweep))
            current_sweep = []
            destinations_seen = set()
        if not current_sweep:
            current_sweep_stream = block.stream_key
        current_sweep.append(block)
        destinations_seen.add(block.storage_id)
    if current_sweep:
        sweeps.append(tuple(current_sweep))
    return tuple(sweeps)


def _anchored_empty_prefix_lengths(
    frames: Iterable[BDOFrame],
    events: Iterable[BDOEvent],
    spec: EventSpec,
    hydration_windows: dict[
        tuple[str, int, str, int, int, int],
        tuple[float, float],
    ],
) -> set[int]:
    """Infer an empty-wrapper length from a broad anchored town cohort.

    Older complete profiles may predate ``repeat_stride`` persistence. The
    dedicated character-load boundary still lets us prove a prefix without a
    patch table: exact count-zero wrappers at one length plus decoded nonempty
    records must form a tightly timed cohort spanning at least eight numeric
    destinations. Competing lengths fail closed.
    """

    count_offset = spec.record_count_offset
    destination_offset = spec.source_context_offset
    if count_offset is None or destination_offset is None:
        return set()

    empty_by_stream_and_length: dict[
        tuple[tuple[str, int, str, int, int, int], int],
        list[tuple[float, int, bool]],
    ] = {}
    for frame in frames:
        if frame.opcode != spec.opcode or frame.length > spec.item_offset:
            continue
        if max(count_offset + 2, destination_offset + 4) > len(frame.message):
            continue
        if int.from_bytes(frame.message[count_offset : count_offset + 2], "little"):
            continue
        storage_id = int.from_bytes(
            frame.message[destination_offset : destination_offset + 4],
            "little",
        )
        if storage_id == 0:
            continue
        stream_key = (
            frame.context.flow.source_ip,
            frame.context.flow.source_port,
            frame.context.flow.destination_ip,
            frame.context.flow.destination_port,
            frame.context.flow_generation,
            frame.opcode,
        )
        window = hydration_windows.get(stream_key)
        if window is None or not window[0] <= frame.context.timestamp <= window[1]:
            continue
        empty_by_stream_and_length.setdefault(
            (stream_key, frame.length),
            [],
        ).append((frame.context.timestamp, storage_id, True))

    nonempty_by_stream: dict[
        tuple[str, int, str, int, int, int],
        list[tuple[float, int, bool]],
    ] = {}
    for event in events:
        if event.opcode != spec.opcode or not event.storage_id:
            continue
        frame_key = _event_frame_key(event)
        stream_key = (
            event.flow.source_ip,
            event.flow.source_port,
            event.flow.destination_ip,
            event.flow.destination_port,
            frame_key.flow_generation,
            spec.opcode,
        )
        nonempty_by_stream.setdefault(stream_key, []).append(
            (event.timestamp, event.storage_id, False)
        )

    proven: set[int] = set()
    for (stream_key, prefix_length), empty_points in empty_by_stream_and_length.items():
        points = sorted(
            empty_points + nonempty_by_stream.get(stream_key, []),
            key=lambda point: point[0],
        )
        burst: list[tuple[float, int, bool]] = []

        def consider() -> None:
            if (
                burst
                and any(point[2] for point in burst)
                and len({point[1] for point in burst})
                >= _STORAGE_HYDRATION_MIN_DESTINATIONS
            ):
                proven.add(prefix_length)

        for point in points:
            if burst and (
                point[0] - burst[-1][0] > _STORAGE_HYDRATION_BURST_GAP_SECONDS
                or point[0] - burst[0][0] > _STORAGE_HYDRATION_MAX_BURST_SECONDS
            ):
                consider()
                burst = []
            burst.append(point)
        consider()
    return proven


def _storage_empty_schemas(
    events: Iterable[BDOEvent],
    specs: Iterable[EventSpec],
    *,
    frames: Iterable[BDOFrame] = (),
    hydration_anchors: Iterable[_HydrationAnchor] = (),
) -> tuple[
    dict[int, tuple[_StorageEmptySchema, ...]],
    dict[tuple[str, int, str, int, int, int], tuple[float, float]],
]:
    """Learn empty-wrapper geometry from profile authority and live records."""

    events = tuple(events)
    frames = tuple(frames)
    hydration_anchors = tuple(hydration_anchors)
    storage_specs = tuple(
        spec for spec in specs if spec.label == "INVENTORY_TO_STORAGE"
    )
    by_opcode = _spec_candidates_by_opcode(storage_specs)
    observed_strides: dict[EventSpec, set[int]] = {
        spec: set() for spec in storage_specs
    }
    windows: dict[tuple[str, int, str, int, int, int], tuple[float, float]] = {}
    groups: dict[tuple[_FrameKey, float, Optional[int]], list[BDOEvent]] = {}
    for event in events:
        groups.setdefault(
            (_event_frame_key(event), event.timestamp, event.opcode),
            [],
        ).append(event)
        if event.opcode is None:
            continue
        window_key = (
            event.flow.source_ip,
            event.flow.source_port,
            event.flow.destination_ip,
            event.flow.destination_port,
            _event_frame_key(event).flow_generation,
            event.opcode,
        )
        previous = windows.get(window_key)
        windows[window_key] = (
            event.timestamp if previous is None else min(previous[0], event.timestamp),
            event.timestamp if previous is None else max(previous[1], event.timestamp),
        )

    # The dedicated character-state API has a stronger semantic boundary than
    # the continuous event stream: a proven inventory hydration generation.
    # It may therefore retain exact count-zero storage envelopes even when an
    # account has too few populated towns to satisfy the live classifier's
    # conservative nonempty-destination threshold. The profile still supplies
    # the authoritative opcode, count column, destination column, and stride;
    # this only supplies the bounded time window in which those envelopes may
    # represent the same character-load cohort.
    for anchor in hydration_anchors:
        anchor_key = anchor.frame_key
        for spec in storage_specs:
            window_key = (
                anchor_key.source_ip,
                anchor_key.source_port,
                anchor_key.destination_ip,
                anchor_key.destination_port,
                anchor_key.flow_generation,
                spec.opcode,
            )
            start = anchor.timestamp
            end = anchor.timestamp + _STORAGE_HYDRATION_EPOCH_SECONDS
            previous = windows.get(window_key)
            windows[window_key] = (
                start if previous is None else min(previous[0], start),
                end if previous is None else max(previous[1], end),
            )

    for (_frame_key_value, _timestamp, opcode), group in groups.items():
        if opcode is None or len(group) < 2:
            continue
        offsets = sorted(
            event.record_offset
            for event in group
            if isinstance(event.record_offset, int)
            and not isinstance(event.record_offset, bool)
        )
        if len(offsets) != len(group):
            continue
        strides = {later - earlier for earlier, later in zip(offsets, offsets[1:])}
        if len(strides) != 1:
            continue
        stride = next(iter(strides))
        if stride <= 0:
            continue
        for spec in by_opcode.get(opcode, ()):
            base_length = spec.single_record_message_length
            if base_length is None or offsets[0] != spec.item_offset:
                continue
            message_lengths = {
                event.message_length
                for event in group
                if isinstance(event.message_length, int)
                and not isinstance(event.message_length, bool)
            }
            if len(message_lengths) != 1:
                continue
            message_length = next(iter(message_lengths))
            if message_length != base_length + (len(group) - 1) * stride:
                continue
            observed_strides[spec].add(stride)

    schemas_by_opcode: dict[int, list[_StorageEmptySchema]] = {}
    for spec in storage_specs:
        strides = observed_strides[spec]
        selected_stride: Optional[int] = None
        prefix_length: Optional[int] = None
        if len(strides) == 1:
            selected_stride = next(iter(strides))
        elif len(strides) > 1:
            # Conflicting same-capture record geometry is stronger evidence
            # of ambiguity than a coincidental count-zero cohort. Fail closed.
            continue
        elif spec.repeat_stride is not None:
            selected_stride = spec.repeat_stride
        else:
            # Only a profile with no record-stride authority may learn its
            # empty-envelope length from the dedicated character-load cohort.
            # A weaker cohort must never override observed or calibrated
            # repeated-record geometry.
            inferred_prefixes = _anchored_empty_prefix_lengths(
                frames,
                events,
                spec,
                windows,
            )
            if len(inferred_prefixes) != 1:
                continue
            prefix_length = next(iter(inferred_prefixes))
        base_length = spec.single_record_message_length
        count_offset = spec.record_count_offset
        destination_offset = spec.source_context_offset
        if (
            count_offset is None
            or destination_offset is None
        ):
            continue
        if prefix_length is None:
            if base_length is None or selected_stride is None:
                continue
            prefix_length = base_length - selected_stride
        if (
            prefix_length < 5
            or count_offset + 2 > prefix_length
            or destination_offset + 4 > prefix_length
            or prefix_length > spec.item_offset
        ):
            continue
        schemas_by_opcode.setdefault(spec.opcode, []).append(
            _StorageEmptySchema(spec=spec, prefix_length=prefix_length)
        )
    return (
        {opcode: tuple(schemas) for opcode, schemas in schemas_by_opcode.items()},
        windows,
    )


def _empty_storage_envelope_id(
    frame: BDOFrame,
    schema: _StorageEmptySchema,
    hydration_windows: dict[
        tuple[str, int, str, int, int, int],
        tuple[float, float],
    ],
) -> Optional[int]:
    """Return a town only from a learned, in-cohort count-zero envelope."""

    spec = schema.spec
    count_offset = spec.record_count_offset
    destination_offset = spec.source_context_offset
    if count_offset is None or destination_offset is None:
        return None
    if frame.length != schema.prefix_length or frame.length > spec.item_offset:
        return None
    if max(count_offset + 2, destination_offset + 4) > len(frame.message):
        return None
    if int.from_bytes(frame.message[count_offset : count_offset + 2], "little") != 0:
        return None
    window_key = (
        frame.context.flow.source_ip,
        frame.context.flow.source_port,
        frame.context.flow.destination_ip,
        frame.context.flow.destination_port,
        frame.context.flow_generation,
        frame.opcode,
    )
    window = hydration_windows.get(window_key)
    if window is None or not (
        window[0] - _STORAGE_EMPTY_WINDOW_MARGIN_SECONDS
        <= frame.context.timestamp
        <= window[1] + _STORAGE_EMPTY_WINDOW_MARGIN_SECONDS
    ):
        return None
    storage_id = int.from_bytes(
        frame.message[destination_offset : destination_offset + 4],
        "little",
    )
    # The calibrated column is authoritative even when a new town has not yet
    # been added to the display-name registry. Preserve its numeric identity so
    # coverage and decoder health can report the unresolved mapping instead of
    # silently dropping an otherwise proven empty destination.
    return storage_id or None


def _assemble_storage(
    specs: tuple[EventSpec, ...],
    frames: tuple[BDOFrame, ...],
    events: tuple[BDOEvent, ...],
    *,
    observations: Optional[tuple[_StorageGroupObservation, ...]] = None,
    hydration_anchors: Iterable[_HydrationAnchor] = (),
) -> _StorageAssembly:
    events = tuple(events)
    unresolved = sum(event.storage_id is None for event in events)
    records_missing_instance = sum(
        event.storage_instance is None for event in events
    )
    resolved_events = tuple(
        event for event in events if event.storage_id is not None
    )
    if observations is None:
        observations = _storage_group_observations(
            frames,
            resolved_events,
            specs,
            hydration_anchors=hydration_anchors,
        )
    unknown_empty_envelopes = sum(
        observation.empty and observation.storage_id not in STORAGE_LOCATIONS
        for observation in observations
    )
    sweeps = _infer_storage_sweeps(observations)
    selected_sweep = len(sweeps) if sweeps else None
    selected_blocks = (
        {block.storage_id: block for block in sweeps[-1]} if sweeps else {}
    )

    raw_counts: dict[int, int] = {}
    missing_instance_counts: dict[int, int] = {}
    all_records: dict[int, dict[str, SnapshotItem]] = {}
    group_counts: dict[int, int] = {}
    empty_ids: set[int] = set()
    source_opcodes: dict[int, set[int]] = {}
    message_lengths: dict[int, set[int]] = {}
    for observation in observations:
        storage_id = observation.storage_id
        raw_counts[storage_id] = (
            raw_counts.get(storage_id, 0) + observation.raw_records
        )
        missing_instance_counts[storage_id] = (
            missing_instance_counts.get(storage_id, 0)
            + observation.missing_instance_records
        )
        group_counts[storage_id] = group_counts.get(storage_id, 0) + 1
        source_opcodes.setdefault(storage_id, set()).add(observation.opcode)
        if observation.message_length is not None:
            message_lengths.setdefault(storage_id, set()).add(
                observation.message_length
            )
        if observation.empty:
            empty_ids.add(storage_id)
        for item in observation.items:
            all_records.setdefault(storage_id, {})[item.instance] = item

    sweeps_by_storage: dict[int, int] = {}
    for sweep in sweeps:
        for block in sweep:
            sweeps_by_storage[block.storage_id] = (
                sweeps_by_storage.get(block.storage_id, 0) + 1
            )

    all_ids = set(group_counts)
    summaries: list[StorageSnapshotSummary] = []
    diagnostics_by_id: dict[int, StorageDestinationDiagnostics] = {}
    for storage_id in all_ids:
        location = storage_location(storage_id)
        selected_block = selected_blocks.get(storage_id)
        current_state_observed = selected_block is not None
        items_by_instance: dict[str, SnapshotItem] = {}
        selected_records = 0
        selected_groups = 0
        selected_missing_instance_records = 0
        current_empty: Optional[bool] = None
        if selected_block is not None:
            selected_records = sum(
                group.raw_records for group in selected_block.groups
            )
            selected_groups = len(selected_block.groups)
            selected_missing_instance_records = sum(
                group.missing_instance_records for group in selected_block.groups
            )
            current_empty = selected_block.empty
            if not current_empty:
                for group in selected_block.groups:
                    for item in group.items:
                        items_by_instance[item.instance] = item
        raw_count = raw_counts.get(storage_id, 0)
        missing_instance_records = missing_instance_counts.get(storage_id, 0)
        groups = group_counts.get(storage_id, 0)
        summaries.append(
            StorageSnapshotSummary(
                storage_id=storage_id,
                name=location.name if location is not None else None,
                name_confidence=(
                    location.confidence if location is not None else None
                ),
                items=tuple(
                    sorted(
                        items_by_instance.values(), key=lambda item: item.instance
                    )
                ),
                current_state_observed=current_state_observed,
                current_empty=current_empty,
                current_identity_complete=(
                    selected_missing_instance_records == 0
                    if current_state_observed
                    else None
                ),
            )
        )
        diagnostics_by_id[storage_id] = StorageDestinationDiagnostics(
            storage_id=storage_id,
            raw_records=raw_count,
            duplicate_records=max(
                0,
                raw_count
                - missing_instance_records
                - len(all_records.get(storage_id, {})),
            ),
            groups=groups,
            empty_envelope_seen=storage_id in empty_ids,
            selected_records=selected_records,
            selected_groups=selected_groups,
            sweeps_observed=sweeps_by_storage.get(storage_id, 0),
            selected_sweep=(selected_sweep if current_state_observed else None),
            missing_instance_records=missing_instance_records,
            selected_missing_instance_records=selected_missing_instance_records,
            source_opcodes=tuple(sorted(source_opcodes.get(storage_id, ()))),
            message_lengths=tuple(sorted(message_lengths.get(storage_id, ()))),
        )

    summaries.sort(
        key=lambda summary: (
            summary.name is None,
            summary.name.casefold() if summary.name is not None else "",
            summary.storage_id,
        )
    )
    return _StorageAssembly(
        summaries=tuple(summaries),
        diagnostics=tuple(
            diagnostics_by_id[summary.storage_id] for summary in summaries
        ),
        records_without_destination=unresolved,
        records_missing_instance=records_missing_instance,
        sweeps_observed=len(sweeps),
        selected_sweep=selected_sweep,
        unknown_empty_envelopes=unknown_empty_envelopes,
    )
