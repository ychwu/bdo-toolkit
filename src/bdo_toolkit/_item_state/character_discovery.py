"""Structural discovery of the remote-inventory family, without known owner IDs."""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Iterator
from ..raw.models import RawMessage
from .character_profile import CharacterLayoutProfile, CharacterTable


def uint(b: bytes) -> int:
    return int.from_bytes(b, "little")


@dataclass
class Candidate:
    opcode: int
    header: int
    stride: int
    count: int
    rows: list[bytes]

    def layout(self, **fields: int) -> CharacterTable:
        return CharacterTable(
            self.opcode, self.header, self.stride, self.count, None, fields
        )


def counted(
    messages: list[bytes], low: int, high: int, min_rows: int
) -> Iterator[Candidate]:
    first = messages[0]
    for offset in range(5, min(30, len(first) - 1)):
        n = uint(first[offset : offset + 2])
        if n < min_rows:
            continue
        for stride in range(low, high + 1):
            header = len(first) - n * stride
            if not offset + 2 <= header <= 48:
                continue
            if all(
                len(b) == header + stride * uint(b[offset : offset + 2])
                for b in messages
            ):
                rows = [
                    b[p : p + stride]
                    for b in messages
                    for p in range(header, len(b), stride)
                ]
                yield Candidate(uint(first[3:5]), header, stride, offset, rows)


@dataclass
class Evidence:
    remote: CharacterTable
    roster: CharacterTable
    stat_candidates: list[tuple[Candidate, int]]
    chunk: Candidate
    neighbors: list[RawMessage]


def _small(
    frames: list[RawMessage],
) -> Iterator[tuple[Candidate, int, frozenset[bytes]]]:
    for f in frames:
        if not 75 <= f.length <= 4096:
            continue
        for t in counted([f.message], 9, 36, 6):
            if len(t.rows) > 128:
                continue
            for pos in range(t.stride - 7):
                ids = frozenset(r[pos : pos + 8] for r in t.rows)
                if len(ids) == len(t.rows) and bytes(8) not in ids:
                    yield t, pos, ids


def _bursts(frames: list[RawMessage]) -> Iterator[list[RawMessage]]:
    groups: dict[tuple, list[RawMessage]] = defaultdict(list)
    for f in frames:
        groups[f.flow, f.connection_epoch, f.opcode].append(f)
    for group in groups.values():
        burst: list[RawMessage] = []
        for f in sorted(group, key=lambda x: x.observed_at):
            if burst and f.observed_at - burst[0].observed_at > 1:
                yield burst
                burst = []
            burst.append(f)
        if burst:
            yield burst


def _remote_fields(t: Candidate, o: int) -> Iterator[CharacterTable]:
    for c in range(t.stride):
        if {r[c] for r in t.rows} != {0, 1, 17}:
            continue
        for s in range(t.stride):
            if s == c or any(r[s] > 63 for r in t.rows if r[c] == 1):
                continue
            if len({(r[o : o + 8], r[c], r[s]) for r in t.rows}) != len(t.rows):
                continue
            qty = [
                p
                for p in range(t.stride - 7)
                if all(
                    1 <= uint(r[p : p + 8]) <= 2**40
                    and (r[c] != 1 or uint(r[p : p + 8]) == 1)
                    for r in t.rows
                )
                and any(uint(r[p : p + 8]) > 1 for r in t.rows)
            ]
            items = [
                p
                for p in range(t.stride - 3)
                if all(
                    0 < uint(r[p : p + 3]) < 0x400000 and r[p + 3] <= 32 for r in t.rows
                )
                and len({r[p : p + 4] for r in t.rows}) > len(t.rows) // 8
            ]
            for i in items:
                for q in qty:
                    spans = [
                        range(o, o + 8),
                        range(c, c + 1),
                        range(s, s + 1),
                        range(i, i + 4),
                        range(q, q + 8),
                    ]
                    if len({v for span in spans for v in span}) == 22:
                        yield t.layout(owner=o, container=c, slot=s, item=i, quantity=q)


def _metadata_col(t: Candidate, owner: int) -> dict[str, int]:
    cols = []
    for p in range(t.stride - 1):
        if p < owner + 8 and owner < p + 2:
            continue
        values = {uint(r[p : p + 2]) for r in t.rows}
        if (
            65535 in values
            and len(values) >= 3
            and all(v == 65535 or v < 64 for v in values)
        ):
            cols.append(p)
    return {"metadata": cols[0]} if len(cols) == 1 else {}


def discover_core(
    frames: list[RawMessage], previous: CharacterLayoutProfile | None = None
) -> list[Evidence]:
    results = []
    geometry_checks = 0
    for burst in _bursts(frames):
        blind = (
            len({f.length for f in burst}) >= 2 and max(f.length for f in burst) > 4096
        )
        old = previous.tables["remote"] if previous else None
        geometries: Iterable[Candidate]
        if blind:
            geometries = counted([f.message for f in burst], 48, 112, 6)
        elif old and burst[0].opcode == old.opcode and old.count_offset is not None:
            # A trusted layout can be checked with a single chunk. It still
            # has to pass the independent owner, inventory and slot proofs.
            try:
                rows = [row for frame in burst for row in old.rows(frame.message)]
            except ValueError:
                continue
            geometries = (
                Candidate(old.opcode, old.header, old.stride, old.count_offset, rows),
            )
        else:
            continue
        anchor = burst[0]
        near: list[RawMessage] | None = None
        for t in geometries:
            if near is None:
                near = [
                    f
                    for f in frames
                    if f.flow == anchor.flow
                    and f.connection_epoch == anchor.connection_epoch
                    and abs(f.observed_at - anchor.observed_at) <= 30
                ]
            geometry_checks += 1
            if geometry_checks > 128 or len(t.rows) > 32768:
                raise ValueError(
                    "character calibration candidate search limit exceeded"
                )
            small = []
            id_cells = 0
            for candidate in _small(near):
                id_cells += len(candidate[2])
                if id_cells > 131072:
                    raise ValueError(
                        "character calibration owner-table search limit exceeded"
                    )
                small.append(candidate)
            for o in range(t.stride - 7):
                ids = frozenset(r[o : o + 8] for r in t.rows)
                if bytes(8) in ids or not 4 <= len(ids) <= min(128, len(t.rows) // 3):
                    continue
                exact = [
                    (tab, pos)
                    for tab, pos, values in small
                    if values == ids and tab.opcode != t.opcode
                ]
                supersets: dict[frozenset[bytes], list[tuple[Candidate, int]]] = (
                    defaultdict(list)
                )
                for tab, pos, values in small:
                    if ids < values and tab.opcode != t.opcode:
                        supersets[values].append((tab, pos))
                corroborated = [
                    group
                    for group in supersets.values()
                    if len({v.opcode for v, _ in group}) >= 2
                ]
                if not exact or len(corroborated) != 1:
                    continue
                group = corroborated[0]
                # Identify the compact roster by its independently varying uint16 field.
                rosters = [
                    (tab, pos, col)
                    for tab, pos in group
                    if (col := _metadata_col(tab, pos))
                ]
                choices = {
                    (
                        tab.opcode,
                        tab.header,
                        tab.stride,
                        tab.count,
                        pos,
                        col["metadata"],
                    )
                    for tab, pos, col in rosters
                }
                if len(choices) != 1:
                    continue
                tab, pos, col = rosters[0]
                stats = [
                    (st, offset)
                    for st, offset in exact
                    if st.opcode not in {g.opcode for g, _ in group}
                ]
                if not stats:
                    continue
                for remote in _remote_fields(t, o):
                    if not blind and (
                        old is None
                        or any(old.fields.get(k) != v for k, v in remote.fields.items())
                    ):
                        continue
                    results.append(
                        Evidence(remote, tab.layout(owner=pos, **col), stats, t, near)
                    )
                    if len(results) > 1:
                        return results
    return results
