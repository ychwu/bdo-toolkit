"""Opcode-agnostic structural classifier for Arena of Solare leaderboards."""

from __future__ import annotations

import hashlib
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict, Iterable, Optional, Sequence, cast

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


type _FamilyKey = tuple[FlowKey, int, int, int]


def _family_key(frame: BDOFrame) -> _FamilyKey:
    return (
        frame.context.flow,
        frame.context.flow_generation,
        frame.opcode,
        frame.length,
    )


def _u32le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _stream_offset(frame: BDOFrame) -> int:
    return frame.stream_sequence if frame.stream_sequence is not None else frame.index


def _stream_end(frame: BDOFrame) -> int:
    if frame.stream_sequence is not None:
        return frame.stream_sequence + frame.length
    # ``frame.index`` is an ordinal, not a byte coordinate.
    return frame.index + 1


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
    first_observation_ordinal: int = 0
    completion_observation_ordinal: int = 0
    frames: tuple[BDOFrame, ...] = field(
        default=(),
        repr=False,
        compare=False,
    )
    flow_generation: int = 0

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
    flow_generation: int = 0


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
    def exact_cross_check(self) -> int:
        """Number of shared rank/name pairs supporting the best overall table."""

        ranked = self.rich or self.ranked_candidate
        overall = self.overall or self.partial_overall
        if ranked is None or overall is None:
            return 0
        overlap = _cross_check_overlap(ranked, overall.names, overall.ranks)
        return overlap or 0

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


def _identifier_starts_here(data: bytes, offset: int) -> bool:
    """Return whether ``offset`` is the start, not a suffix, of an identifier."""

    if not _read_player_identifier(data, offset):
        return False
    if (
        offset >= 2
        and data[offset - 1] == 0
        and data[offset - 2] in PLAYER_NAME_BYTES
    ):
        return False
    return True


def _candidate_name_pairs(frames: Sequence[BDOFrame]) -> list[_NamePair]:
    if not frames:
        return []
    first = frames[0].message
    columns: list[tuple[int, tuple[str, ...]]] = []
    for offset in range(BDO_HEADER_SIZE, len(first) - 1):
        if not _identifier_starts_here(first, offset):
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
    """Find the class-table rank column without requiring ranks 21..100.

    The rich response is the union of twenty entries per class.  Global ranks
    1 through 20 must therefore be present regardless of class distribution:
    no player in that prefix can have twenty same-class players ahead of them.
    Rank 21 and later may legitimately be absent when one class contributes
    more than twenty players to the independent overall top 100.
    """

    scan_end = min(record_stride - 4, DISCOVERY_FIELD_SCAN_LIMIT)
    for offset in range(BDO_HEADER_SIZE, max(BDO_HEADER_SIZE, scan_end + 1)):
        if record_stride + offset + 4 > frames[0].length:
            continue
        prefix_frames = frames[:10]
        prefix = tuple(
            value
            for frame in prefix_frames
            for value in (
                _u32le(frame.message, offset),
                _u32le(frame.message, record_stride + offset),
            )
        )
        if prefix != tuple(range(1, len(prefix) + 1)):
            continue
        values = prefix + tuple(
            value
            for frame in frames[len(prefix_frames) :]
            for value in (
                _u32le(frame.message, offset),
                _u32le(frame.message, record_stride + offset),
            )
        )
        if len(values) < 100 or len(set(values)) != len(values):
            continue
        if any(value <= 0 for value in values):
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


def _looks_like_class_table_prefix(
    frames: Sequence[BDOFrame], record_stride: int
) -> bool:
    """Reject an exact top-100 prefix cut from another rich class table.

    A rich response is arranged in consecutive 20-player class groups.  Its
    first 50 frames therefore expose five distinct known class codes in five
    exact runs of twenty.  An idle capture boundary is not evidence that such
    a prefix is the independent overall table.
    """

    record_count = len(frames) * 2
    if record_count != 100:
        return False
    scan_end = min(record_stride - 1, DISCOVERY_FIELD_SCAN_LIMIT)
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
        groups = tuple(
            values[start : start + 20]
            for start in range(0, record_count, 20)
        )
        codes = tuple(group[0] for group in groups)
        if (
            len(set(codes)) == len(codes)
            and all(code in CLASS_NAMES for code in codes)
            and all(all(value == group[0] for value in group) for group in groups)
        ):
            return True
    return False


def _observation_bounds(
    frames: Sequence[BDOFrame],
    observation_ordinals: dict[int, int],
) -> tuple[int, int]:
    ordinals = tuple(observation_ordinals[id(frame)] for frame in frames)
    return min(ordinals), max(ordinals)


def _discover_ranked_family(
    key: _FamilyKey,
    frames: Sequence[BDOFrame],
    observation_ordinals: dict[int, int],
) -> Optional[DiscoveredSolareFamily]:
    if len(frames) * 2 < DISCOVERY_MIN_RICH_RECORDS:
        return None
    for name_pair in _candidate_name_pairs(frames):
        rank_field = _infer_increasing_rank_field(frames, name_pair.stride)
        if rank_field is None:
            continue
        rank_offset, ranks = rank_field
        flow, flow_generation, opcode, frame_length = key
        first_observation, completion_observation = _observation_bounds(
            frames,
            observation_ordinals,
        )
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
            last_stream_end=max(_stream_end(frame) for frame in frames),
            flow_generation=flow_generation,
            first_observation_ordinal=first_observation,
            completion_observation_ordinal=completion_observation,
            frames=tuple(frames),
        )
    return None


def _discover_rich_family(
    key: _FamilyKey,
    frames: Sequence[BDOFrame],
    ranked: DiscoveredSolareFamily,
) -> Optional[DiscoveredSolareFamily]:
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
        flow_generation=ranked.flow_generation,
        first_observation_ordinal=ranked.first_observation_ordinal,
        completion_observation_ordinal=ranked.completion_observation_ordinal,
        frames=ranked.frames,
    )


def _discover_overall_family(
    key: _FamilyKey,
    frames: Sequence[BDOFrame],
    rich: DiscoveredSolareFamily,
    observation_ordinals: dict[int, int],
) -> Optional[DiscoveredSolareFamily]:
    if (
        len(frames) != 50
        or key[0] != rich.flow
        or key[1] != rich.flow_generation
    ):
        return None
    first_stream_offset = min(_stream_offset(frame) for frame in frames)
    distance = first_stream_offset - rich.last_stream_end
    if not 0 <= distance <= DISCOVERY_MAX_FAMILY_DISTANCE:
        return None
    class_prefix_by_stride: dict[int, bool] = {}
    for name_pair in _candidate_name_pairs(frames):
        if name_pair.stride not in class_prefix_by_stride:
            class_prefix_by_stride[name_pair.stride] = (
                _looks_like_class_table_prefix(frames, name_pair.stride)
            )
        if class_prefix_by_stride[name_pair.stride]:
            continue
        rank_field = _infer_increasing_rank_field(frames, name_pair.stride)
        if rank_field is None:
            continue
        rank_offset, ranks = rank_field
        if ranks != tuple(range(1, 101)):
            continue
        if _cross_check_overlap(rich, name_pair.names, ranks) is None:
            continue
        flow, flow_generation, opcode, frame_length = key
        first_observation, completion_observation = _observation_bounds(
            frames,
            observation_ordinals,
        )
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
            last_stream_end=max(_stream_end(frame) for frame in frames),
            flow_generation=flow_generation,
            first_observation_ordinal=first_observation,
            completion_observation_ordinal=completion_observation,
            frames=tuple(frames),
        )
    return None


def _discover_partial_overall_family(
    key: _FamilyKey,
    frames: Sequence[BDOFrame],
    ranked: DiscoveredSolareFamily,
    observation_ordinals: dict[int, int],
) -> Optional[DiscoveredSolareFamily]:
    if len(frames) * 2 < DISCOVERY_MIN_PARTIAL_OVERALL_RECORDS:
        return None
    if (
        len(frames) >= 50
        or key[0] != ranked.flow
        or key[1] != ranked.flow_generation
    ):
        return None
    first_stream_offset = min(_stream_offset(frame) for frame in frames)
    distance = first_stream_offset - ranked.last_stream_end
    if not 0 <= distance <= DISCOVERY_MAX_FAMILY_DISTANCE:
        return None
    for name_pair in _candidate_name_pairs(frames):
        rank_field = _infer_partial_overall_rank_field(frames, name_pair.stride)
        if rank_field is None:
            continue
        rank_offset, ranks = rank_field
        if _cross_check_overlap(ranked, name_pair.names, ranks) is None:
            continue
        flow, flow_generation, opcode, frame_length = key
        first_observation, completion_observation = _observation_bounds(
            frames,
            observation_ordinals,
        )
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
            last_stream_end=max(_stream_end(frame) for frame in frames),
            flow_generation=flow_generation,
            first_observation_ordinal=first_observation,
            completion_observation_ordinal=completion_observation,
            frames=tuple(frames),
        )
    return None


def _cross_check_overlap(
    ranked: DiscoveredSolareFamily,
    overall_names: Sequence[str],
    overall_ranks: Sequence[int],
) -> Optional[int]:
    """Return exact shared pairs, or ``None`` on weak/contradictory evidence.

    Rank and name are checked in both directions.  The second direction catches
    an overall-only rank reusing a rich-table name at a different rank.  Twenty
    exact overlaps are required because that is the guaranteed prefix for a
    union of class leaderboards capped at twenty entries each.
    """

    ranked_by_rank = dict(zip(ranked.ranks, ranked.names))
    ranked_by_name = dict(zip(ranked.names, ranked.ranks))
    overlap = 0
    for rank, name in zip(overall_ranks, overall_names):
        ranked_name = ranked_by_rank.get(rank)
        if ranked_name is not None:
            if ranked_name != name:
                return None
            overlap += 1
        ranked_rank = ranked_by_name.get(name)
        if ranked_rank is not None and ranked_rank != rank:
            return None
    return overlap if overlap >= 20 else None


def _discover_menu_context(
    key: _FamilyKey, frames: Sequence[BDOFrame]
) -> Optional[SolareMenuContext]:
    if len(frames) != 24:
        return None
    columns: list[tuple[int, tuple[str, ...]]] = []
    first = frames[0].message
    for offset in range(BDO_HEADER_SIZE, len(first) - 1):
        # Most byte offsets cannot begin a UTF-16LE player identifier.  Reject
        # those from the first frame before reading the same offset from all 24
        # frames; this keeps menu-context probing cheap on unrelated traffic.
        if not _identifier_starts_here(first, offset):
            continue
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
    flow, flow_generation, opcode, frame_length = key
    return SolareMenuContext(
        flow=flow,
        opcode=opcode,
        frame_length=frame_length,
        frame_count=len(frames),
        player_slots_per_frame=len(collapsed),
        record_stride=strides[0],
        unique_names=len(set(all_names)),
        flow_generation=flow_generation,
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


def _rank_reset_starts(frames: Sequence[BDOFrame]) -> tuple[int, ...]:
    """Locate response boundaries from the invariant rank-1..20 prefix.

    Both Solare ranked families carry two rows per frame.  A complete rich
    response and the overall response therefore begin with ranks 1/2, 3/4,
    ... 19/20 at one shared field/stride geometry.  Finding that short prefix
    is enough to split repeated refreshes without knowing an opcode or layout.
    """

    if len(frames) < 10:
        return ()

    encoded_one = (1).to_bytes(4, "little")
    encoded_two = (2).to_bytes(4, "little")
    starts: list[int] = []
    for start in range(len(frames) - 9):
        first = frames[start].message
        scan_end = min(len(first) - 4, DISCOVERY_FIELD_SCAN_LIMIT)
        rank_offset = first.find(
            encoded_one,
            BDO_HEADER_SIZE,
            scan_end + 4,
        )
        found = False
        while 0 <= rank_offset <= scan_end and not found:
            half = len(first) // 2
            second_start = max(
                rank_offset + 1,
                rank_offset + half - DISCOVERY_NAME_PAIR_TOLERANCE,
            )
            second_end = min(
                len(first) - 4,
                rank_offset + half + DISCOVERY_NAME_PAIR_TOLERANCE,
            )
            second_offset = first.find(
                encoded_two,
                second_start,
                second_end + 4,
            )
            while 0 <= second_offset <= second_end:
                stride = second_offset - rank_offset
                if all(
                    _u32le(frame.message, rank_offset) == ordinal * 2 + 1
                    and _u32le(frame.message, rank_offset + stride)
                    == ordinal * 2 + 2
                    for ordinal, frame in enumerate(frames[start : start + 10])
                ):
                    starts.append(start)
                    found = True
                    break
                second_offset = first.find(
                    encoded_two,
                    second_offset + 1,
                    second_end + 4,
                )
            rank_offset = first.find(
                encoded_one,
                rank_offset + 1,
                scan_end + 4,
            )
    return tuple(starts)


def _rank_reset_windows(
    frames: Sequence[BDOFrame],
    expected_count: int,
    *,
    _starts: Optional[tuple[int, ...]] = None,
) -> tuple[Sequence[BDOFrame], ...]:
    """Return each reset-aligned generation, capped at its expected size."""

    starts = _rank_reset_starts(frames) if _starts is None else _starts
    if not starts:
        return ()

    windows: list[Sequence[BDOFrame]] = []
    for index, start in enumerate(starts):
        next_start = starts[index + 1] if index + 1 < len(starts) else len(frames)
        stop = min(start + expected_count, next_start)
        windows.append(frames[start:stop])
    return tuple(windows)


def _overall_generation_is_closed(
    group: Sequence[BDOFrame],
    window: Sequence[BDOFrame],
    overall: DiscoveredSolareFamily,
    *,
    allow_trailing_overall: bool,
) -> bool:
    """Prove that a 50-frame overall candidate does not continue as rich.

    Another frame in the same family must restart at ranks 1/2; ranks 101/102
    prove that the candidate was only a rich prefix.  A trailing live candidate
    remains tentative until the caller declares an end-of-burst boundary.
    """

    last_position = next(
        index for index, frame in enumerate(group) if frame is window[-1]
    )
    if last_position + 1 < len(group):
        following = group[last_position + 1]
        return (
            _u32le(following.message, overall.rank_offset) == 1
            and _u32le(
                following.message,
                overall.rank_offset + overall.record_stride,
            )
            == 2
        )
    if allow_trailing_overall:
        return True
    return False


_ANALYSIS_CACHE_MAX_ENTRIES = 64
_CACHE_MISS = object()


def _family_analysis_identity(
    family: DiscoveredSolareFamily,
) -> tuple[object, ...]:
    """Return a compact identity for one cache-owned structural result."""

    first_frame = id(family.frames[0]) if family.frames else None
    last_frame = id(family.frames[-1]) if family.frames else None
    return (
        family.flow,
        family.flow_generation,
        family.opcode,
        family.frame_length,
        family.frame_count,
        family.record_stride,
        family.name_offset,
        family.rank_offset,
        family.class_offset,
        family.first_stream_offset,
        family.last_stream_end,
        first_frame,
        last_frame,
    )


class _DiscoveryAnalysisCache:
    """Bound repeated structural work to exact retained frame windows.

    The live tracker owns one instance and clears it whenever its retained
    deque evicts history.  Cache keys contain frame identities rather than
    frame references, while successful values may own only frames that are
    already retained by that deque.  A small LRU ceiling also keeps manual,
    unusually frequent refreshes from accumulating quadratic window results.
    """

    def __init__(self) -> None:
        self._items: OrderedDict[tuple[object, ...], object] = OrderedDict()

    @property
    def entry_count(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        self._items.clear()

    def _window_key(
        self,
        role: str,
        key: _FamilyKey,
        frames: Sequence[BDOFrame],
        *extra: object,
    ) -> tuple[object, ...]:
        return (role, key, tuple(id(frame) for frame in frames), *extra)

    def _get(self, key: tuple[object, ...]) -> object:
        value = self._items.get(key, _CACHE_MISS)
        if value is not _CACHE_MISS:
            self._items.move_to_end(key)
        return value

    def _put(self, key: tuple[object, ...], value: object) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        while len(self._items) > _ANALYSIS_CACHE_MAX_ENTRIES:
            self._items.popitem(last=False)

    def rank_reset_starts(
        self,
        key: _FamilyKey,
        frames: Sequence[BDOFrame],
    ) -> tuple[int, ...]:
        cache_key = self._window_key("rank-resets", key, frames)
        cached = self._get(cache_key)
        if cached is not _CACHE_MISS:
            return cast(tuple[int, ...], cached)
        result = _rank_reset_starts(frames)
        self._put(cache_key, result)
        return result

    def menu_context(
        self,
        key: _FamilyKey,
        frames: Sequence[BDOFrame],
    ) -> Optional[SolareMenuContext]:
        cache_key = self._window_key("menu", key, frames)
        cached = self._get(cache_key)
        if cached is not _CACHE_MISS:
            return cast(Optional[SolareMenuContext], cached)
        result = _discover_menu_context(key, frames)
        self._put(cache_key, result)
        return result

    def ranked_and_rich(
        self,
        key: _FamilyKey,
        frames: Sequence[BDOFrame],
        observation_ordinals: dict[int, int],
    ) -> tuple[
        Optional[DiscoveredSolareFamily],
        Optional[DiscoveredSolareFamily],
    ]:
        observation_bounds = _observation_bounds(frames, observation_ordinals)
        cache_key = self._window_key(
            "ranked-rich",
            key,
            frames,
            observation_bounds,
        )
        cached = self._get(cache_key)
        if cached is not _CACHE_MISS:
            return cast(
                tuple[
                    Optional[DiscoveredSolareFamily],
                    Optional[DiscoveredSolareFamily],
                ],
                cached,
            )
        ranked = _discover_ranked_family(key, frames, observation_ordinals)
        rich = (
            _discover_rich_family(key, frames, ranked)
            if ranked is not None
            else None
        )
        result = (ranked, rich)
        self._put(cache_key, result)
        return result

    def overall_family(
        self,
        key: _FamilyKey,
        frames: Sequence[BDOFrame],
        rich: DiscoveredSolareFamily,
        observation_ordinals: dict[int, int],
    ) -> Optional[DiscoveredSolareFamily]:
        observation_bounds = _observation_bounds(frames, observation_ordinals)
        cache_key = self._window_key(
            "overall",
            key,
            frames,
            _family_analysis_identity(rich),
            observation_bounds,
        )
        cached = self._get(cache_key)
        if cached is not _CACHE_MISS:
            return cast(Optional[DiscoveredSolareFamily], cached)
        result = _discover_overall_family(
            key,
            frames,
            rich,
            observation_ordinals,
        )
        self._put(cache_key, result)
        return result

    def partial_overall_family(
        self,
        key: _FamilyKey,
        frames: Sequence[BDOFrame],
        ranked: DiscoveredSolareFamily,
        observation_ordinals: dict[int, int],
    ) -> Optional[DiscoveredSolareFamily]:
        observation_bounds = _observation_bounds(frames, observation_ordinals)
        cache_key = self._window_key(
            "partial-overall",
            key,
            frames,
            _family_analysis_identity(ranked),
            observation_bounds,
        )
        cached = self._get(cache_key)
        if cached is not _CACHE_MISS:
            return cast(Optional[DiscoveredSolareFamily], cached)
        result = _discover_partial_overall_family(
            key,
            frames,
            ranked,
            observation_ordinals,
        )
        self._put(cache_key, result)
        return result


def discover_solare(
    frames: Iterable[BDOFrame],
    *,
    allow_trailing_overall: bool = True,
    _analysis_cache: Optional[_DiscoveryAnalysisCache] = None,
) -> SolareDiscoveryResult:
    """Identify a complete Solare snapshot without seeded opcode values.

    ``allow_trailing_overall`` is false during an active live burst.  That
    prevents a still-growing rich generation from being accepted at its
    50-frame prefix.  Replay/end-of-burst callers pass a finalized input and
    may prove an exact 50-frame generation at the tail.
    """

    analysis_cache = (
        _analysis_cache
        if _analysis_cache is not None
        else _DiscoveryAnalysisCache()
    )
    unique_frames: list[BDOFrame] = []
    observation_ordinals: dict[int, int] = {}
    seen: set[tuple[object, ...]] = set()
    for frame in frames:
        identity = (
            frame.context.flow,
            frame.context.flow_generation,
            (
                frame.stream_sequence
                if frame.stream_sequence is not None
                else frame.index
            ),
            frame.length,
            hashlib.blake2s(frame.message, digest_size=8).digest(),
        )
        if identity in seen:
            continue
        seen.add(identity)
        observation_ordinals[id(frame)] = len(unique_frames)
        unique_frames.append(frame)

    grouped: DefaultDict[_FamilyKey, list[BDOFrame]] = defaultdict(list)
    for frame in unique_frames:
        if frame.flag != 0:
            continue
        if not DISCOVERY_MIN_FRAME_LENGTH <= frame.length <= DISCOVERY_MAX_FRAME_LENGTH:
            continue
        grouped[_family_key(frame)].append(frame)

    eligible = {
        key: sorted(group, key=_stream_offset)
        for key, group in grouped.items()
        if len(group) >= DISCOVERY_MIN_FAMILY_FRAMES
    }
    # Preserve the public summary shape/count semantics even though internal
    # classification now keeps connection generations separate.
    summary_counts: Counter[tuple[int, int]] = Counter()
    for key, group in eligible.items():
        summary_counts[(key[2], key[3])] += len(group)
    summaries = tuple(
        sorted(
            (
                (opcode, frame_length, count)
                for (opcode, frame_length), count in summary_counts.items()
            ),
            key=lambda summary: (-summary[2], summary[0], summary[1]),
        )
    )
    menu_contexts: list[SolareMenuContext] = []
    ranked_candidates: list[DiscoveredSolareFamily] = []
    rich_candidates: list[DiscoveredSolareFamily] = []
    for key, group in eligible.items():
        # Menu/history context is one exact 24-frame response.  Probe the
        # first window once (the tracker cache reuses it as a family grows).
        # If capture began in a partial response, the finalized trailing edge
        # gets one retry without making every ranked milestone rescan 24 large
        # frames.  A validated first window also preserves repeated menus of
        # any length instead of losing context after the second response.
        if len(group) >= 24:
            first_menu_window = group[:24]
            menu_context = analysis_cache.menu_context(key, first_menu_window)
            if menu_context is not None:
                menu_contexts.append(menu_context)
            elif len(group) <= 48 or allow_trailing_overall:
                last_menu_window = group[-24:]
                if last_menu_window[0] is not first_menu_window[0]:
                    menu_context = analysis_cache.menu_context(
                        key,
                        last_menu_window,
                    )
                    if menu_context is not None:
                        menu_contexts.append(menu_context)
        reset_starts = analysis_cache.rank_reset_starts(key, group)
        for window in _rank_reset_windows(
            group,
            310,
            _starts=reset_starts,
        ):
            ranked, rich = analysis_cache.ranked_and_rich(
                key,
                window,
                observation_ordinals,
            )
            if ranked is not None:
                ranked_candidates.append(ranked)
                if rich is not None:
                    rich_candidates.append(rich)

    ranked_candidates.sort(
        key=lambda candidate: (
            -candidate.record_count,
            candidate.completion_observation_ordinal,
            candidate.first_observation_ordinal,
        )
    )
    rich_candidates.sort(
        key=lambda candidate: (
            candidate.completion_observation_ordinal,
            candidate.first_observation_ordinal,
            candidate.opcode,
            candidate.frame_length,
        )
    )
    complete_pairs: list[
        tuple[DiscoveredSolareFamily, DiscoveredSolareFamily]
    ] = []
    for rich in rich_candidates:
        rich_key = (
            rich.flow,
            rich.flow_generation,
            rich.opcode,
            rich.frame_length,
        )
        for key, group in eligible.items():
            if key == rich_key:
                continue
            reset_starts = analysis_cache.rank_reset_starts(key, group)
            for window in _rank_reset_windows(
                group,
                50,
                _starts=reset_starts,
            ):
                overall = analysis_cache.overall_family(
                    key,
                    window,
                    rich,
                    observation_ordinals,
                )
                if overall is not None and _overall_generation_is_closed(
                    group,
                    window,
                    overall,
                    allow_trailing_overall=allow_trailing_overall,
                ):
                    complete_pairs.append((rich, overall))

    if complete_pairs:
        rich, overall = min(
            complete_pairs,
            key=lambda pair: (
                max(
                    pair[0].completion_observation_ordinal,
                    pair[1].completion_observation_ordinal,
                ),
                min(
                    pair[0].first_observation_ordinal,
                    pair[1].first_observation_ordinal,
                ),
                pair[0].opcode,
                pair[1].opcode,
            ),
        )
        return SolareDiscoveryResult(
            scanned_frames=len(unique_frames),
            candidate_families=summaries,
            rich=rich,
            overall=overall,
            ranked_candidate=rich,
            partial_overall=overall,
            menu_context=menu_contexts[0] if menu_contexts else None,
        )

    rich_by_key: dict[_FamilyKey, DiscoveredSolareFamily] = {}
    for item in rich_candidates:
        rich_by_key.setdefault(
            (
                item.flow,
                item.flow_generation,
                item.opcode,
                item.frame_length,
            ),
            item,
        )
    for ranked in ranked_candidates:
        ranked_key = (
            ranked.flow,
            ranked.flow_generation,
            ranked.opcode,
            ranked.frame_length,
        )
        for key, group in eligible.items():
            if key == ranked_key:
                continue
            for window in _edge_windows(group, 50):
                partial_overall = analysis_cache.partial_overall_family(
                    key,
                    window,
                    ranked,
                    observation_ordinals,
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

    if family.frames:
        return family.frames

    return tuple(
        sorted(
            (
                frame
                for frame in frames
                if frame.context.flow == family.flow
                and frame.context.flow_generation == family.flow_generation
                and frame.opcode == family.opcode
                and frame.length == family.frame_length
                and _stream_offset(frame) >= family.first_stream_offset
                and _stream_end(frame) <= family.last_stream_end
            ),
            key=_stream_offset,
        )
    )
