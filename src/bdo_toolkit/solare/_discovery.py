"""Opcode-agnostic structural classifier for Arena of Solare leaderboards."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import DefaultDict, Iterable, Optional, Sequence

from bdo_toolkit._protocol import BDOFrame, FlowKey

from ._constants import (
    BDO_HEADER_SIZE,
    CLASS_NAMES,
    DISCOVERY_FIELD_SCAN_LIMIT,
    DISCOVERY_MAX_CLASS_GROUPS,
    DISCOVERY_MAX_FAMILY_DISTANCE,
    DISCOVERY_MAX_FRAME_LENGTH,
    DISCOVERY_MIN_FAMILY_FRAMES,
    DISCOVERY_MIN_FRAME_LENGTH,
    DISCOVERY_MIN_PARTIAL_OVERALL_RECORDS,
    DISCOVERY_MIN_RICH_RECORDS,
    DISCOVERY_NAME_PAIR_TOLERANCE,
    PLAYER_NAME_BYTES,
)


def _u32le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _stream_offset(frame: BDOFrame) -> int:
    return frame.stream_sequence if frame.stream_sequence is not None else frame.index


@dataclass(frozen=True)
class DiscoveredSolareFamily:
    """One structurally identified family; opcode is reported, not trusted."""

    role: str
    flow: FlowKey
    opcode: int
    frame_length: int
    frame_count: int
    record_stride: int
    name_offset: int
    rank_offset: int
    names: tuple[str, ...]
    ranks: tuple[int, ...]
    first_stream_offset: int
    last_stream_end: int
    class_offset: Optional[int] = None
    class_codes: tuple[int, ...] = ()
    class_counts: tuple[tuple[int, int], ...] = ()

    @property
    def record_count(self) -> int:
        return len(self.names)


@dataclass(frozen=True)
class SolareMenuContext:
    flow: FlowKey
    opcode: int
    frame_length: int
    frame_count: int
    player_slots_per_frame: int
    record_stride: int
    unique_names: int


@dataclass(frozen=True)
class SolareDiscoveryResult:
    scanned_frames: int
    candidate_families: tuple[tuple[int, int, int], ...]
    rich: Optional[DiscoveredSolareFamily] = None
    overall: Optional[DiscoveredSolareFamily] = None
    ranked_candidate: Optional[DiscoveredSolareFamily] = None
    partial_overall: Optional[DiscoveredSolareFamily] = None
    menu_context: Optional[SolareMenuContext] = None

    @property
    def confirmed(self) -> bool:
        return self.rich is not None and self.overall is not None

    @property
    def status(self) -> str:
        if self.confirmed:
            return "complete"
        if self.ranked_candidate is not None and self.partial_overall is not None:
            return "detected-incomplete"
        if self.rich is not None:
            return "rich-candidate"
        if self.ranked_candidate is not None:
            return "ranked-partial"
        if self.menu_context is not None:
            return "menu-context"
        return "inconclusive"


@dataclass(frozen=True)
class _NamePair:
    first_offset: int
    second_offset: int
    stride: int
    names: tuple[str, ...]


def _read_player_identifier(data: bytes, offset: int, max_chars: int = 32) -> str:
    if offset < 0:
        return ""
    raw = bytearray()
    for index in range(max_chars):
        position = offset + index * 2
        if position + 1 >= len(data):
            return ""
        low = data[position]
        high = data[position + 1]
        if low == 0 and high == 0:
            return raw.decode("ascii") if raw else ""
        if high != 0 or low not in PLAYER_NAME_BYTES:
            return ""
        raw.append(low)
    return ""


def _candidate_name_pairs(frames: Sequence[BDOFrame]) -> list[_NamePair]:
    if not frames:
        return []
    first = frames[0].message
    columns: list[tuple[int, tuple[str, ...]]] = []
    for offset in range(BDO_HEADER_SIZE, len(first) - 1):
        if not _read_player_identifier(first, offset):
            continue
        values = tuple(
            _read_player_identifier(frame.message, offset) for frame in frames
        )
        if not all(values) or len(set(values)) != len(values):
            continue
        columns.append((offset, values))

    pairs: list[_NamePair] = []
    for index, (first_offset, first_values) in enumerate(columns):
        for second_offset, second_values in columns[index + 1 :]:
            stride = second_offset - first_offset
            if abs(stride - (len(first) / 2)) > DISCOVERY_NAME_PAIR_TOLERANCE:
                continue
            interleaved = tuple(
                value for pair in zip(first_values, second_values) for value in pair
            )
            if len(set(interleaved)) != len(interleaved):
                continue
            pairs.append(
                _NamePair(
                    first_offset=first_offset,
                    second_offset=second_offset,
                    stride=stride,
                    names=interleaved,
                )
            )
    return pairs


def _infer_increasing_rank_field(
    frames: Sequence[BDOFrame], record_stride: int
) -> Optional[tuple[int, tuple[int, ...]]]:
    scan_end = min(record_stride - 4, DISCOVERY_FIELD_SCAN_LIMIT)
    for offset in range(BDO_HEADER_SIZE, max(BDO_HEADER_SIZE, scan_end + 1)):
        if record_stride + offset + 4 > frames[0].length:
            continue
        values = tuple(
            value
            for frame in frames
            for value in (
                _u32le(frame.message, offset),
                _u32le(frame.message, record_stride + offset),
            )
        )
        first_hundred = min(100, len(values))
        if values[:first_hundred] != tuple(range(1, first_hundred + 1)):
            continue
        if len(values) < 100 or len(set(values)) != len(values):
            continue
        if any(left >= right for left, right in zip(values, values[1:])):
            continue
        return offset, values
    return None


def _infer_partial_overall_rank_field(
    frames: Sequence[BDOFrame], record_stride: int
) -> Optional[tuple[int, tuple[int, ...]]]:
    scan_end = min(record_stride - 4, DISCOVERY_FIELD_SCAN_LIMIT)
    for offset in range(BDO_HEADER_SIZE, max(BDO_HEADER_SIZE, scan_end + 1)):
        if record_stride + offset + 4 > frames[0].length:
            continue
        values = tuple(
            value
            for frame in frames
            for value in (
                _u32le(frame.message, offset),
                _u32le(frame.message, record_stride + offset),
            )
        )
        if len(values) < DISCOVERY_MIN_PARTIAL_OVERALL_RECORDS:
            continue
        if len(set(values)) != len(values):
            continue
        if not all(1 <= value <= 100 for value in values):
            continue
        if any(left >= right for left, right in zip(values, values[1:])):
            continue
        return offset, values
    return None


def _infer_class_field(
    frames: Sequence[BDOFrame], record_stride: int
) -> Optional[tuple[int, tuple[int, ...], tuple[tuple[int, int], ...]]]:
    scan_end = min(record_stride - 1, DISCOVERY_FIELD_SCAN_LIMIT)
    candidates: list[
        tuple[int, tuple[int, ...], tuple[tuple[int, int], ...]]
    ] = []
    for offset in range(BDO_HEADER_SIZE, max(BDO_HEADER_SIZE, scan_end + 1)):
        if record_stride + offset >= frames[0].length:
            continue
        values = tuple(
            value
            for frame in frames
            for value in (
                frame.message[offset],
                frame.message[record_stride + offset],
            )
        )
        counts = Counter(values)
        if not 20 <= len(counts) <= DISCOVERY_MAX_CLASS_GROUPS:
            continue
        if not counts or any(count != 20 for count in counts.values()):
            continue
        candidates.append((offset, values, tuple(sorted(counts.items()))))

    if not candidates:
        return None
    return max(
        candidates,
        key=lambda candidate: (
            sum(code in CLASS_NAMES for code, _count in candidate[2]),
            -candidate[0],
        ),
    )


def _discover_ranked_family(
    key: tuple[FlowKey, int, int], frames: Sequence[BDOFrame]
) -> Optional[DiscoveredSolareFamily]:
    if len(frames) * 2 < DISCOVERY_MIN_RICH_RECORDS:
        return None
    for name_pair in _candidate_name_pairs(frames):
        rank_field = _infer_increasing_rank_field(frames, name_pair.stride)
        if rank_field is None:
            continue
        rank_offset, ranks = rank_field
        flow, opcode, frame_length = key
        return DiscoveredSolareFamily(
            role="ranked-partial",
            flow=flow,
            opcode=opcode,
            frame_length=frame_length,
            frame_count=len(frames),
            record_stride=name_pair.stride,
            name_offset=name_pair.first_offset,
            rank_offset=rank_offset,
            names=name_pair.names,
            ranks=ranks,
            first_stream_offset=min(_stream_offset(frame) for frame in frames),
            last_stream_end=max(
                _stream_offset(frame) + frame.length for frame in frames
            ),
        )
    return None


def _discover_rich_family(
    key: tuple[FlowKey, int, int],
    frames: Sequence[BDOFrame],
    ranked: Optional[DiscoveredSolareFamily] = None,
) -> Optional[DiscoveredSolareFamily]:
    ranked = ranked or _discover_ranked_family(key, frames)
    if ranked is None:
        return None
    class_field = _infer_class_field(frames, ranked.record_stride)
    if class_field is None:
        return None
    class_offset, class_codes, class_counts = class_field
    if len(ranked.names) != sum(count for _code, count in class_counts):
        return None
    # A balanced prefix is not a complete leaderboard.  The three validated
    # generations all carry every currently known Arena class exactly twenty
    # times (31 x 20 = 620). Requiring that full roster prevents a capture gap
    # that happens to leave 20 balanced class groups from being promoted as an
    # atomic snapshot. A newly added/removed class therefore fails closed until
    # the toolkit's class registry is reviewed.
    expected_class_counts = tuple((code, 20) for code in sorted(CLASS_NAMES))
    if class_counts != expected_class_counts:
        return None
    return DiscoveredSolareFamily(
        role="rich",
        flow=ranked.flow,
        opcode=ranked.opcode,
        frame_length=ranked.frame_length,
        frame_count=ranked.frame_count,
        record_stride=ranked.record_stride,
        name_offset=ranked.name_offset,
        rank_offset=ranked.rank_offset,
        class_offset=class_offset,
        names=ranked.names,
        ranks=ranked.ranks,
        class_codes=class_codes,
        class_counts=class_counts,
        first_stream_offset=ranked.first_stream_offset,
        last_stream_end=ranked.last_stream_end,
    )


def _discover_overall_family(
    key: tuple[FlowKey, int, int],
    frames: Sequence[BDOFrame],
    rich: DiscoveredSolareFamily,
) -> Optional[DiscoveredSolareFamily]:
    if len(frames) != 50 or key[0] != rich.flow:
        return None
    first_stream_offset = min(_stream_offset(frame) for frame in frames)
    distance = first_stream_offset - rich.last_stream_end
    if not 0 <= distance <= DISCOVERY_MAX_FAMILY_DISTANCE:
        return None
    expected_names = rich.names[:100]
    for name_pair in _candidate_name_pairs(frames):
        if name_pair.names != expected_names:
            continue
        rank_field = _infer_increasing_rank_field(frames, name_pair.stride)
        if rank_field is None:
            continue
        rank_offset, ranks = rank_field
        if ranks != tuple(range(1, 101)):
            continue
        flow, opcode, frame_length = key
        return DiscoveredSolareFamily(
            role="overall",
            flow=flow,
            opcode=opcode,
            frame_length=frame_length,
            frame_count=len(frames),
            record_stride=name_pair.stride,
            name_offset=name_pair.first_offset,
            rank_offset=rank_offset,
            names=name_pair.names,
            ranks=ranks,
            first_stream_offset=first_stream_offset,
            last_stream_end=max(
                _stream_offset(frame) + frame.length for frame in frames
            ),
        )
    return None


def _discover_partial_overall_family(
    key: tuple[FlowKey, int, int],
    frames: Sequence[BDOFrame],
    ranked: DiscoveredSolareFamily,
) -> Optional[DiscoveredSolareFamily]:
    if len(frames) * 2 < DISCOVERY_MIN_PARTIAL_OVERALL_RECORDS:
        return None
    if len(frames) >= 50 or key[0] != ranked.flow:
        return None
    first_stream_offset = min(_stream_offset(frame) for frame in frames)
    distance = first_stream_offset - ranked.last_stream_end
    if not 0 <= distance <= DISCOVERY_MAX_FAMILY_DISTANCE:
        return None
    rich_top100 = {
        rank: name
        for rank, name in zip(ranked.ranks, ranked.names)
        if 1 <= rank <= 100
    }
    for name_pair in _candidate_name_pairs(frames):
        rank_field = _infer_partial_overall_rank_field(frames, name_pair.stride)
        if rank_field is None:
            continue
        rank_offset, ranks = rank_field
        if any(
            rich_top100.get(rank) != name
            for rank, name in zip(ranks, name_pair.names)
        ):
            continue
        flow, opcode, frame_length = key
        return DiscoveredSolareFamily(
            role="overall-partial",
            flow=flow,
            opcode=opcode,
            frame_length=frame_length,
            frame_count=len(frames),
            record_stride=name_pair.stride,
            name_offset=name_pair.first_offset,
            rank_offset=rank_offset,
            names=name_pair.names,
            ranks=ranks,
            first_stream_offset=first_stream_offset,
            last_stream_end=max(
                _stream_offset(frame) + frame.length for frame in frames
            ),
        )
    return None


def _discover_menu_context(
    key: tuple[FlowKey, int, int], frames: Sequence[BDOFrame]
) -> Optional[SolareMenuContext]:
    if len(frames) != 24:
        return None
    columns: list[tuple[int, tuple[str, ...]]] = []
    first = frames[0].message
    for offset in range(BDO_HEADER_SIZE, len(first) - 1):
        values = tuple(
            _read_player_identifier(frame.message, offset) for frame in frames
        )
        if not all(values) or len(set(values)) < 12:
            continue
        columns.append((offset, values))

    collapsed: list[tuple[int, tuple[str, ...]]] = []
    for offset, values in columns:
        if collapsed and offset - collapsed[-1][0] <= 64:
            continue
        collapsed.append((offset, values))
    if len(collapsed) != 5:
        return None
    offsets = [offset for offset, _values in collapsed]
    strides = [right - left for left, right in zip(offsets, offsets[1:])]
    if len(set(strides)) != 1:
        return None
    all_names = [name for _offset, values in collapsed for name in values]
    if not 40 <= len(set(all_names)) <= len(all_names):
        return None
    flow, opcode, frame_length = key
    return SolareMenuContext(
        flow=flow,
        opcode=opcode,
        frame_length=frame_length,
        frame_count=len(frames),
        player_slots_per_frame=len(collapsed),
        record_stride=strides[0],
        unique_names=len(set(all_names)),
    )


def _edge_windows(
    frames: Sequence[BDOFrame], expected_count: int
) -> tuple[Sequence[BDOFrame], ...]:
    """Return chronological edge windows for repeated same-family responses.

    A capture may begin midway through one refresh and then contain a complete
    retry, or may contain one complete refresh followed by a partial retry.
    Testing the earliest and latest exact-size windows lets either complete
    response survive without accepting a mixed window across the rank reset.
    """

    if len(frames) <= expected_count:
        return (frames,)
    first = frames[:expected_count]
    last = frames[-expected_count:]
    if first[0] is last[0]:
        return (first,)
    return (first, last)


def discover_solare(frames: Iterable[BDOFrame]) -> SolareDiscoveryResult:
    """Identify a complete Solare snapshot without seeded opcode values."""

    unique_frames: list[BDOFrame] = []
    seen: set[tuple[object, ...]] = set()
    for frame in frames:
        identity = (
            frame.context.flow,
            frame.stream_sequence,
            frame.length,
            hashlib.blake2s(frame.message, digest_size=8).digest(),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique_frames.append(frame)

    grouped: DefaultDict[tuple[FlowKey, int, int], list[BDOFrame]] = defaultdict(list)
    for frame in unique_frames:
        if frame.flag != 0:
            continue
        if not DISCOVERY_MIN_FRAME_LENGTH <= frame.length <= DISCOVERY_MAX_FRAME_LENGTH:
            continue
        grouped[(frame.context.flow, frame.opcode, frame.length)].append(frame)

    eligible = {
        key: sorted(group, key=_stream_offset)
        for key, group in grouped.items()
        if len(group) >= DISCOVERY_MIN_FAMILY_FRAMES
    }
    summaries = tuple(
        sorted(
            ((key[1], key[2], len(group)) for key, group in eligible.items()),
            key=lambda summary: (-summary[2], summary[0], summary[1]),
        )
    )

    menu_contexts: list[SolareMenuContext] = []
    ranked_candidates: list[DiscoveredSolareFamily] = []
    rich_candidates: list[DiscoveredSolareFamily] = []
    for key, group in eligible.items():
        for window in _edge_windows(group, 24):
            menu_context = _discover_menu_context(key, window)
            if menu_context is not None:
                menu_contexts.append(menu_context)
        for window in _edge_windows(group, 310):
            ranked = _discover_ranked_family(key, window)
            if ranked is not None:
                ranked_candidates.append(ranked)
            rich = _discover_rich_family(key, window, ranked)
            if rich is not None:
                rich_candidates.append(rich)

    ranked_candidates.sort(
        key=lambda candidate: (-candidate.record_count, candidate.first_stream_offset)
    )
    rich_candidates.sort(
        key=lambda candidate: (-candidate.record_count, candidate.first_stream_offset)
    )
    for rich in rich_candidates:
        rich_key = (rich.flow, rich.opcode, rich.frame_length)
        for key, group in eligible.items():
            if key == rich_key:
                continue
            for window in _edge_windows(group, 50):
                overall = _discover_overall_family(key, window, rich)
                if overall is not None:
                    return SolareDiscoveryResult(
                        scanned_frames=len(unique_frames),
                        candidate_families=summaries,
                        rich=rich,
                        overall=overall,
                        ranked_candidate=rich,
                        partial_overall=overall,
                        menu_context=menu_contexts[0] if menu_contexts else None,
                    )

    rich_by_key: dict[tuple[FlowKey, int, int], DiscoveredSolareFamily] = {}
    for item in rich_candidates:
        rich_by_key.setdefault((item.flow, item.opcode, item.frame_length), item)
    for ranked in ranked_candidates:
        ranked_key = (ranked.flow, ranked.opcode, ranked.frame_length)
        for key, group in eligible.items():
            if key == ranked_key:
                continue
            for window in _edge_windows(group, 50):
                partial_overall = _discover_partial_overall_family(
                    key, window, ranked
                )
                if partial_overall is not None:
                    return SolareDiscoveryResult(
                        scanned_frames=len(unique_frames),
                        candidate_families=summaries,
                        rich=rich_by_key.get(ranked_key),
                        ranked_candidate=ranked,
                        partial_overall=partial_overall,
                        menu_context=menu_contexts[0] if menu_contexts else None,
                    )

    return SolareDiscoveryResult(
        scanned_frames=len(unique_frames),
        candidate_families=summaries,
        rich=rich_candidates[0] if rich_candidates else None,
        ranked_candidate=(
            rich_candidates[0]
            if rich_candidates
            else (ranked_candidates[0] if ranked_candidates else None)
        ),
        menu_context=menu_contexts[0] if menu_contexts else None,
    )


def family_frames(
    frames: Iterable[BDOFrame], family: DiscoveredSolareFamily
) -> tuple[BDOFrame, ...]:
    """Return ordered frames belonging to one discovered family."""

    return tuple(
        sorted(
            (
                frame
                for frame in frames
                if frame.context.flow == family.flow
                and frame.opcode == family.opcode
                and frame.length == family.frame_length
                and _stream_offset(frame) >= family.first_stream_offset
                and _stream_offset(frame) + frame.length <= family.last_stream_end
            ),
            key=_stream_offset,
        )
    )
