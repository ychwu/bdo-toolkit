"""Calibration of the optional families after independent owner and slot discovery."""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
import math
import struct
from ..raw.models import RawMessage
from .character_discovery import Evidence, Candidate, counted, uint
from .character_profile import NOVEMBER, CharacterTable, CharacterLayoutProfile


@dataclass
class Witnesses:
    stats: dict[bytes, tuple[float, float, float]] = field(default_factory=dict)
    life: dict[int, int] = field(default_factory=dict)
    stones: dict[tuple[bytes, int, int], tuple[int, int]] = field(default_factory=dict)


def reference_witnesses(
    frames: list[RawMessage], profile: CharacterLayoutProfile
) -> Witnesses:
    """Keep positive references in memory only; caller explicitly pairs capture and profile."""
    result = Witnesses()
    for family in ("stats", "life", "remote"):
        t = profile.tables.get(family)
        if not t:
            continue
        f = t.fields
        for frame in frames:
            if frame.opcode != t.opcode:
                continue
            for r in t.rows(frame.message):
                if family == "stats":
                    owner = r[f["owner"] : f["owner"] + 8]
                    v = tuple(
                        struct.unpack_from("<f", r, f[k])[0]
                        for k in ("dp", "ap", "aap")
                    )
                    if owner in result.stats:
                        raise ValueError("multiple reference stat epochs")
                    result.stats[owner] = (v[0], v[1], v[2])
                elif family == "life":
                    slot = r[f["slot"]]
                    if slot in result.life:
                        raise ValueError("multiple reference life-gear epochs")
                    result.life[slot] = uint(r[f["item"] : f["item"] + 3])
                elif (
                    "stone1" in f
                    and r[f["container"]] == 1
                    and r[f["slot"]] in (32, 33)
                ):
                    key = (
                        r[f["owner"] : f["owner"] + 8],
                        r[f["slot"]],
                        uint(r[f["item"] : f["item"] + 4]),
                    )
                    if key in result.stones:
                        raise ValueError("duplicate reference artifact")
                    result.stones[key] = (
                        uint(r[f["stone1"] : f["stone1"] + 4]),
                        uint(r[f["stone2"] : f["stone2"] + 4]),
                    )
    return result


def unique(tables: list[CharacterTable]) -> CharacterTable | None:
    first = next(iter(tables), None)
    return first if first and all(t == first for t in tables) else None


def remote_sockets(e: Evidence, refs: Witnesses) -> CharacterTable:
    t = e.remote
    fields = dict(t.fields)
    forbidden: set[int] = set()
    for k, n in (
        ("owner", 8),
        ("container", 1),
        ("slot", 1),
        ("item", 4),
        ("quantity", 8),
    ):
        forbidden.update(range(fields[k], fields[k] + n))
    found = []
    # Alchemy stones can populate this region too. They neither confirm nor
    # contradict the socket layout of equipped artifacts.
    structural_rows = [
        r for r in e.chunk.rows
        if not (r[fields["container"]] == 1 and r[fields["slot"]] == 27)
    ]
    for p in range(t.stride - 7):
        if forbidden.intersection(range(p, p + 8)):
            continue
        rows = [r for r in structural_rows if any(r[p : p + 8])]
        if len(rows) < 2:
            continue

        def artifact(r: bytes) -> bool:
            return r[fields["container"]] == 1 and r[fields["slot"]] in (32, 33)

        vals = [uint(r[j : j + 4]) for r in rows for j in (p, p + 4)]
        structural = (
            all(artifact(r) for r in rows)
            and any(uint(r[p : p + 4]) and uint(r[p + 4 : p + 8]) for r in rows)
            and max(vals) < 0x1000000
            and len(set(vals) - {0}) >= 3
        )
        shared = []
        for r in e.chunk.rows:
            if not artifact(r):
                continue
            key = (
                r[fields["owner"] : fields["owner"] + 8],
                r[fields["slot"]],
                uint(r[fields["item"] : fields["item"] + 4]),
            )
            expected = refs.stones.get(key)
            if expected and all(expected):
                shared.append((expected, (uint(r[p : p + 4]), uint(r[p + 4 : p + 8]))))
        if shared:
            agreements = {a for a, b in shared if a == b}
            if len(agreements) >= 2:
                found.append(p)
        elif structural:
            found.append(p)
    if len(found) == 1:
        fields.update(stone1=found[0], stone2=found[0] + 4)
    return CharacterTable(t.opcode, t.header, t.stride, t.count_offset, None, fields)


def stats_layout(
    e: Evidence, previous: CharacterLayoutProfile, refs: Witnesses
) -> CharacterTable | None:
    candidates = []
    old = previous.tables.get("stats")
    for t, o in e.stat_candidates:
        fields = {}
        for idx, key in enumerate(("dp", "ap", "aap")):
            shared = sorted(
                (r[o : o + 8], r, refs.stats[r[o : o + 8]][idx])
                for r in t.rows
                if r[o : o + 8] in refs.stats
            )
            hits = []
            for p in range(t.stride - 3):
                if p < o + 8 and o < p + 4:
                    continue
                values = [struct.unpack_from("<f", r, p)[0] for r in t.rows]
                if not all(
                    math.isfinite(v) and 0 <= v <= 3000 and v.is_integer()
                    for v in values
                ):
                    continue
                if shared:

                    def confirmed(
                        sample: list[tuple[bytes, bytes, float]], distinct: int
                    ) -> bool:
                        agree = [
                            v
                            for _, row, v in sample
                            if struct.unpack_from("<f", row, p)[0] == v
                        ]
                        return (
                            len(agree) >= max(3, len(sample) * 0.65)
                            and len(set(agree)) >= distinct
                        )

                    if confirmed(shared[::2], 3) and confirmed(shared[1::2], 2):
                        hits.append(p)
                elif old and (
                    old.opcode,
                    old.stride,
                    old.fields.get("owner"),
                    old.fields[key],
                ) == (t.opcode, t.stride, o, p):
                    hits.append(p)
            if len(hits) == 1:
                fields[key] = hits[0]
        if len(fields) == 3 and len(set(fields.values())) == 3:
            candidates.append(t.layout(owner=o, **fields))
    return unique(candidates)


def life_layout(
    e: Evidence, previous: CharacterLayoutProfile, refs: Witnesses
) -> CharacterTable | None:
    candidates = []
    old = previous.tables.get("life")
    for f in e.neighbors:
        if f.length < 1024:
            continue
        for t in counted([f.message], 160, 300, 8):
            quantities = [
                p
                for p in range(t.stride - 7)
                if all(uint(row[p : p + 8]) == 1 for row in t.rows)
            ]
            if not quantities:
                continue
            slots = [
                p
                for p in range(t.stride)
                if all(a[p] < b[p] for a, b in zip(t.rows, t.rows[1:]))
            ]
            for slot in slots:
                for i in range(t.stride - 3):
                    ids = {r[slot]: uint(r[i : i + 3]) for r in t.rows}
                    if not all(0 < n < 0x400000 for n in ids.values()) or any(
                        r[i + 3] > 32 for r in t.rows
                    ):
                        continue
                    if (
                        len(set(ids.values())) <= len(t.rows) // 2
                        or len({r[i + 3] for r in t.rows}) < 3
                    ):
                        continue
                    if (
                        refs.life
                        and len({n for s, n in ids.items() if refs.life.get(s) == n})
                        < 4
                    ):
                        continue
                    for q in quantities:
                        if (
                            len({slot} | set(range(i, i + 4)) | set(range(q, q + 8)))
                            != 13
                        ):
                            continue
                        fields = dict(item=i, quantity=q, slot=slot)
                        # Carry sockets only on the exact already verified layout.
                        if (
                            old
                            and (t.opcode, t.header, t.stride, t.count)
                            == (old.opcode, old.header, old.stride, old.count_offset)
                            and all(old.fields[k] == v for k, v in fields.items())
                        ):
                            fields.update(
                                {
                                    k: v
                                    for k, v in old.fields.items()
                                    if k.startswith("stone")
                                }
                            )
                        candidates.append(t.layout(**fields))
    return unique(candidates)


def active_layouts(
    e: Evidence, previous: CharacterLayoutProfile
) -> dict[str, CharacterTable]:
    """Revalidate equipment against item appearances on a roster owner's portrait."""
    from .characters import corroborates_equipment, _active_equipment, _name

    roster = {
        r[e.roster.fields["owner"] : e.roster.fields["owner"] + 8]
        for f in e.neighbors
        if f.opcode == e.roster.opcode
        for r in e.roster.rows(f.message)
    }
    remote = {
        r[e.remote.fields["owner"] : e.remote.fields["owner"] + 8] for r in e.chunk.rows
    }
    possible = roster - remote
    old = previous.tables.get("active", NOVEMBER.tables["active"])
    width = old.stride
    count = old.fixed_count
    if count is None:
        return {}
    results = []
    for f in e.neighbors:
        header = f.length - count * width
        if not 5 <= header <= 48:
            continue
        fields = {k: old.fields[k] for k in ("item", "quantity")}
        if (f.opcode, header) == (old.opcode, old.header):
            fields.update(old.fields)
        active = CharacterTable(f.opcode, header, width, None, count, fields)
        try:
            occupied = _active_equipment(f.message, active)
        except ValueError:
            continue
        if len({item.raw_item_id for _, item in occupied}) < (
            2 if active == old else 4
        ):
            continue
        for view in e.neighbors:
            if view.opcode == f.opcode or view.length < 3000:
                continue
            present = [o for o in roster if o in view.message]
            if len(present) != 1 or present[0] not in possible:
                continue
            old_view = previous.tables.get("portrait")
            reuse = (
                active == old
                and old_view is not None
                and (view.opcode, view.length) == (old_view.opcode, old_view.stride)
            )
            if reuse and old_view is not None:
                offset = old_view.fields["owner"]
                reuse = view.message[offset : offset + 8] == present[0]
            if not corroborates_equipment(
                view.message, [f.message], active, verified_layout=reuse
            ):
                continue
            results.append((active, view, present[0]))
    equip = unique([t for t, _, _ in results])
    if equip is None or len({owner for _, _, owner in results}) != 1:
        return {}
    owner = results[0][2]
    output = {"active": equip}
    old_portrait = previous.tables.get("portrait")
    portraits = []
    named_pairs = []
    labeled_portraits = []
    for _, view, _ in results:
        pos = view.message.index(owner)
        if (
            old_portrait
            and old_portrait.opcode == view.opcode
            and old_portrait.stride == view.length
        ):
            known = old_portrait.fields["owner"]
            if view.message[known : known + 8] == owner:
                pos = known
        portrait = CharacterTable(view.opcode, 0, view.length, None, 1, dict(owner=pos))
        portraits.append(portrait)
        if not (
            old_portrait
            and old_portrait.opcode == view.opcode
            and old_portrait.fields.get("owner") == pos
            and old_portrait.stride == view.length
            and "name" in old_portrait.fields
        ):
            continue
        p = old_portrait.fields["name"]
        name = _name(view.message[p : p + 60])
        if not name:
            continue
        encoded = name.encode("utf-16le") + b"\0\0"
        np = view.message.find(encoded)
        if (
            np < 0
            or view.message.count(encoded) != 1
            or np + 60 > view.length
            or not (np + 60 <= pos or pos + 8 <= np)
        ):
            continue
        labeled_portraits.append(
            CharacterTable(
                view.opcode, 0, view.length, None, 1, dict(owner=pos, name=np)
            )
        )
        # Multiple frame lengths disambiguate the counted row geometry.
        by: dict[int, list[bytes]] = defaultdict(list)
        for other in e.neighbors:
            if other.opcode != view.opcode:
                by[other.opcode].append(other.message)
        for messages in by.values():
            if len({len(b) for b in messages}) < 2 or not any(
                owner in b and encoded in b for b in messages
            ):
                continue
            for t in counted(messages, 180, 350, 1):
                for r in t.rows:
                    o = r.find(owner)
                    n = r.find(encoded)
                    if (
                        o < 0
                        or n < 0
                        or n + 60 > t.stride
                        or not (n + 60 <= o or o + 8 <= n)
                    ):
                        continue
                    named_pairs.append(
                        (
                            t.layout(owner=o, name=n),
                            CharacterTable(
                                view.opcode,
                                0,
                                view.length,
                                None,
                                1,
                                dict(owner=pos, name=np),
                            ),
                        )
                    )
    if named_pairs and all(pair == named_pairs[0] for pair in named_pairs):
        output["named"], output["portrait"] = named_pairs[0]
    else:
        # Prefer the previous portrait opcode only when its layout and owner
        # position also agree. Otherwise do not pick among multiple witnesses.
        prior = [
            p
            for p in portraits
            if old_portrait
            and p.opcode == old_portrait.opcode
            and p.fields["owner"] == old_portrait.fields["owner"]
            and p.stride == old_portrait.stride
        ]
        chosen = unique(labeled_portraits) or unique(prior or portraits)
        if chosen:
            output["portrait"] = chosen
    return output
