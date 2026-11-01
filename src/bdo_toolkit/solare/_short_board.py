"""Fail-closed fallback for the observed short, terminated class response."""

from collections import Counter, defaultdict
from dataclasses import replace
from typing import Optional, Sequence

from bdo_toolkit._protocol import BDOFrame

from ._constants import DISCOVERY_MIN_RICH_RECORDS, SOLARE_CLASS_ROSTERS
from ._discovery import (
    DiscoveredSolareFamily, _discover_overall_family, _discover_ranked_family,
    _family_key, _overall_generation_is_closed, _read_player_identifier,
    _stream_end, _stream_offset, _u32le,
)


def discover_short_board(
    frames: Sequence[BDOFrame], boundaries: Sequence[BDOFrame], *,
    allow_trailing_overall: bool,
) -> Optional[tuple[DiscoveredSolareFamily, DiscoveredSolareFamily]]:
    # October JP evidence: 17-byte envelope, start flag at payload byte zero,
    # uint16 row count at byte 10. These are reviewed envelope semantics, not
    # opcode, region, player, class or total-row-count exceptions.
    all_frames = sorted({id(f): f for f in (*frames, *boundaries)}.values(),
                        key=lambda f: f.index)
    ordinals = {id(f): i for i, f in enumerate(all_frames)}
    groups = defaultdict(list)
    for f in all_frames:
        if f.flag == 0 and f.stream_sequence is not None:
            groups[(f.context.flow, f.context.flow_generation)].append(f)
    for stream in groups.values():
        stream.sort(key=_stream_offset)
        for start, first in enumerate(stream):
            if not (8192 <= first.length <= 32768 and first.message[5] == 1
                    and first.message[10:12] == b'\x02\x00'):
                continue
            stride, remainder = divmod(first.length - 17, 2)
            if remainder or stride <= 0:
                continue
            pairs = [first]
            terminal = None
            end_index = start
            previous = first
            for end_index in range(start + 1, min(len(stream), start + 512)):
                f = stream[end_index]
                if _stream_offset(f) != _stream_end(previous):
                    break
                previous = f
                if f.opcode != first.opcode:
                    # Complete, bounded interleaved control frames are allowed.
                    if f.length >= 8192:
                        break
                    continue
                if f.length < 17 or f.message[5] != 0:
                    break
                count = int.from_bytes(f.message[10:12], 'little')
                if count == 2 and f.length == first.length:
                    pairs.append(f)
                elif count in (0, 1) and f.length == 17 + count * stride:
                    terminal = f
                    break
                else:
                    break
            if terminal is None or end_index + 50 >= len(stream):
                continue
            tail_count = int.from_bytes(terminal.message[10:12], 'little')
            count = 2 * len(pairs) + tail_count
            if not DISCOVERY_MIN_RICH_RECORDS <= count < max(map(len, SOLARE_CLASS_ROSTERS)) * 20:
                continue
            overall_frames = stream[end_index + 1:end_index + 51]
            if any(_stream_end(a) != _stream_offset(b)
                   for a, b in zip([terminal, *overall_frames], overall_frames)):
                continue
            key = _family_key(overall_frames[0])
            if any(_family_key(f) != key for f in overall_frames) or key[2] == first.opcode:
                continue
            ranked = _discover_ranked_family(_family_key(first), pairs, ordinals)
            if ranked is None or ranked.record_stride != stride:
                continue
            locations = tuple((f, base) for f in pairs for base in (0, stride))
            names, ranks = ranked.names, ranked.ranks
            if tail_count:
                name = _read_player_identifier(terminal.message, ranked.name_offset)
                rank = _u32le(terminal.message, ranked.rank_offset)
                if not name or name in names or rank <= ranks[-1]:
                    continue
                locations += ((terminal, 0),)
                names += (name,)
                ranks += (rank,)
            candidates = []
            for offset in range(17, min(512, stride)):
                codes = tuple(f.message[base + offset] for f, base in locations)
                counts = Counter(codes)
                if (any(set(counts) == set(roster) for roster in SOLARE_CLASS_ROSTERS)
                        and all(1 <= n <= 20 for n in counts.values())
                        and any(n < 20 for n in counts.values())):
                    candidates.append((offset, codes, tuple(sorted(counts.items()))))
            if len(candidates) != 1:
                continue
            offset, codes, counts_tuple = candidates[0]
            rich = replace(
                ranked, role='rich', names=names, ranks=ranks,
                class_offset=offset, class_codes=codes, class_counts=counts_tuple,
                frame_count=len(pairs) + bool(tail_count),
                frames=tuple(pairs) + ((terminal,) if tail_count else ()),
                last_stream_end=_stream_end(terminal),
                completion_observation_ordinal=ordinals[id(terminal)],
                short_record_locations=locations,
            )
            overall = _discover_overall_family(key, overall_frames, rich, ordinals)
            group = [f for f in stream if _family_key(f) == key]
            if (overall is not None
                    and _overall_generation_is_closed(group, overall_frames, overall,
                                                     allow_trailing_overall=allow_trailing_overall)):
                return rich, overall
    return None
