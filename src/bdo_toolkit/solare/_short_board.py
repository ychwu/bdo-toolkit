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
    all_frames = sorted({id(f): f for f in (*frames, *boundaries)}.values(),
                        key=lambda f: f.index)
    ordinals = {id(f): i for i, f in enumerate(all_frames)}
    groups = defaultdict(list)
    for f in all_frames:
        if f.flag == 0 and f.stream_sequence is not None:
            groups[(f.context.flow, f.context.flow_generation)].append(f)
    selected = None
    for stream in groups.values():
        stream.sort(key=_stream_offset)
        for start, first in enumerate(stream):
            if len(first.message) != first.length or not 8192 <= first.length <= 32768:
                continue
            if start and _family_key(stream[start - 1]) == _family_key(first):
                continue
            pairs = [first]
            previous = first
            terminal = None
            for end_index in range(start + 1, min(len(stream), start + 512)):
                f = stream[end_index]
                if _stream_offset(f) != _stream_end(previous) or len(f.message) != f.length:
                    break
                previous = f
                if f.opcode != first.opcode:
                    if f.length >= 8192:
                        break
                    continue
                if f.length != first.length:
                    terminal = f
                    break
                pairs.append(f)
            if terminal is None or len(pairs) * 2 < DISCOVERY_MIN_RICH_RECORDS - 1:
                continue
            ranked = _discover_ranked_family(_family_key(first), pairs, ordinals)
            if ranked is None:
                continue
            stride = ranked.record_stride
            envelope = first.length - 2 * stride
            if not 7 <= envelope <= 32 or terminal.length not in (envelope, envelope + stride):
                continue
            tail_count = int(terminal.length != envelope)
            if ranked.name_offset < envelope or ranked.rank_offset < envelope:
                continue
            if not any(
                all(f.message[pos:pos+2] == b'\x02\x00' for f in pairs)
                and int.from_bytes(terminal.message[pos:pos+2], 'little') == tail_count
                for pos in range(5, envelope - 1)
            ):
                continue
            if not any(first.message[pos] == 1 and terminal.message[pos] == 0
                       and all(f.message[pos] == 0 for f in pairs[1:])
                       for pos in range(5, envelope)):
                continue
            count = 2 * len(pairs) + tail_count
            if not DISCOVERY_MIN_RICH_RECORDS <= count < max(map(len, SOLARE_CLASS_ROSTERS)) * 20:
                continue
            boundary = terminal
            while end_index + 1 < len(stream):
                control = stream[end_index + 1]
                if (control.length >= 8192 or control.opcode == first.opcode
                        or control.length != len(control.message)
                        or _stream_end(boundary) != _stream_offset(control)):
                    break
                end_index += 1
                boundary = control
            overall_frames = stream[end_index + 1:end_index + 51]
            if len(overall_frames) != 50:
                continue
            if any(_stream_end(a) != _stream_offset(b)
                   for a, b in zip([boundary, *overall_frames], overall_frames)):
                continue
            key = _family_key(overall_frames[0])
            if key[2] == first.opcode or any(
                len(f.message) != f.length or _family_key(f) != key for f in overall_frames
            ):
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
            for offset in range(envelope, min(512, stride)):
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
                if selected is not None:
                    # Two distinct complete response pairs in the supplied window.
                    return None
                if not _verified_short_details(rich, overall):
                    continue
                selected = (rich, overall)
    return selected


def _verified_short_details(rich: DiscoveredSolareFamily, overall: DiscoveredSolareFamily) -> bool:
    """Corroborate inferred envelope geometry with both complete detail tables."""
    from ._detail_learning import decode_equipment_table, learn_unknown_solare_details

    players, leaders = learn_unknown_solare_details(
        rich.frames, rich, overall.frames, overall,
        learn_rich=True, learn_overall=True, retain_raw_extensions=False,
    )
    required = {"elo", "performance"}
    return (players is not None and leaders is not None
            and required <= players.capabilities and required <= leaders.capabilities
            and decode_equipment_table(rich.frames, rich, players.players, gear_offset=None) is not None
            and decode_equipment_table(overall.frames, overall, leaders.entries, gear_offset=None) is not None)
