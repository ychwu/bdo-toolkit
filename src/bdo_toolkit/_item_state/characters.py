"""Finite character-load inference for the observed November 2026 NA/EU layout."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from math import isfinite
from struct import unpack_from

from .._protocol import BDOFrame
from .character_models import (
    CharacterItem,
    CharacterLoadout,
    CharacterRoster,
    CharacterSection,
)
from .character_profile import NOVEMBER, CharacterLayoutProfile, CharacterTable
from .character_slots import GEAR, INFERRED_LIFE, LIFE, MAIN_LIFE
from ._records import _FrameKey, _frame_key
from .models import InventorySnapshotSummary

ROSTER, REMOTE, STATS = 0x160C, 0x1543, 0x134C
NAMED, PORTRAIT, ACTIVE, LIFE_GEAR = 0x15EC, 0x0D36, 0x0EA0, 0x0E9E
# Compatibility names for the November wire fixtures.
_LAYOUT = {
    t.opcode: (t.header, t.stride, t.count_offset)
    for t in NOVEMBER.tables.values()
    if t.count_offset is not None
}
OPCODES = frozenset(t.opcode for t in NOVEMBER.tables.values())


def _uint(data: bytes, offset: int, width: int) -> int:
    return int.from_bytes(data[offset : offset + width], "little")


def record_cost(frame: BDOFrame, table: CharacterTable) -> int:
    return max(1, (len(frame.message) - table.header) // table.stride)


def _name(data: bytes) -> str | None:
    try:
        value = data.decode("utf-16le").split("\0", 1)[0]
    except UnicodeDecodeError:
        return None
    return value if value and value.isprintable() else None


class _Sections:
    def __init__(self) -> None:
        self.items: dict[str, list[CharacterItem]] = defaultdict(list)
        self.sources: dict[str, set[str]] = defaultdict(set)

    def add(self, section: str, item: CharacterItem) -> None:
        self.items[section].append(item)
        self.sources[section].add(item.source)

    def section(self, key: str) -> CharacterSection:
        return CharacterSection(
            tuple(self.items[key]), tuple(sorted(self.sources[key])),
            # Remote equipment carries fishing/hunting tools but cannot
            # replace an earlier observation of the dedicated life-skill bag.
            complete=key != "life" or {"active_equipment", "life_equipment"} <= self.sources[key],
        )


def _equipment(
    item: int,
    quantity: int,
    slot: int,
    source: str,
    container: int | None,
    sockets: tuple[int | None, ...],
) -> tuple[str, CharacterItem]:
    activity, role = MAIN_LIFE.get(slot, (None, GEAR.get(slot)))
    return (
        "life" if activity else "gear",
        CharacterItem(item, quantity, source, slot, container, role, activity, sockets),
    )


def _stones(row: bytes, table: CharacterTable) -> tuple[int | None, ...]:
    if "stone1" not in table.fields:
        return ()
    return tuple(
        _uint(row, table.fields[key], 4) or None for key in ("stone1", "stone2")
    )


def _remote(
    messages: list[bytes], owners: set[str], table: CharacterTable
) -> dict[str, _Sections]:
    result: dict[str, _Sections] = defaultdict(_Sections)
    f = table.fields
    seen: set[tuple[str, int, int]] = set()
    for message in messages:
        for row in table.rows(message):
            owner = row[f["owner"] : f["owner"] + 8].hex()
            code, slot = row[f["container"]], row[f["slot"]]
            item, qty = _uint(row, f["item"], 4), _uint(row, f["quantity"], 8)
            key = (owner, code, slot)
            if owner not in owners or key in seen or not item or not qty:
                raise ValueError("unmatched owner, duplicate slot or invalid item")
            seen.add(key)
            if code == 1:
                if qty != 1:
                    raise ValueError("invalid equipped quantity")
                section, entry = _equipment(
                    item,
                    qty,
                    slot,
                    "remote",
                    code,
                    _stones(row, table) if slot in (32, 33) else (),
                )
            else:
                section = {0: "main", 17: "pearl"}.get(code, "other")
                entry = CharacterItem(item, qty, "remote", slot, code)
            result[owner].add(section, entry)
    return result


def _active_equipment(
    message: bytes, table: CharacterTable
) -> list[tuple[str, CharacterItem]]:
    result = []
    for slot, row in enumerate(table.rows(message)):
        item = _uint(row, table.fields["item"], 4)
        if not item:
            continue
        qty = _uint(row, table.fields["quantity"], 8)
        if qty != 1:
            raise ValueError("invalid equipped quantity")
        sockets = _stones(row, table) if slot in (32, 33) else ()
        result.append(_equipment(item, qty, slot, "active_equipment", None, sockets))
    return result


def _life_equipment(message: bytes, table: CharacterTable) -> list[CharacterItem]:
    result = []
    seen = set()
    for row in table.rows(message):
        item, qty, slot = (
            _uint(row, table.fields["item"], 4),
            _uint(row, table.fields["quantity"], 8),
            row[table.fields["slot"]],
        )
        if not item or not qty or slot in seen:
            raise ValueError("invalid or duplicate life slot")
        seen.add(slot)
        activity, role = LIFE.get(slot, (None, None))
        result.append(
            CharacterItem(
                item,
                qty,
                "life_equipment",
                slot,
                None,
                role,
                activity,
                _stones(row, table) if role in ("artifact_1", "artifact_2") else (),
                role_inferred=slot in INFERRED_LIFE,
            )
        )
    return result


def _single(messages: list[bytes]) -> bytes:
    distinct = set(messages)
    if len(distinct) != 1:
        raise ValueError("conflicting or absent tables")
    return distinct.pop()


def corroborates_equipment(
    portrait: bytes,
    messages: list[bytes],
    table: CharacterTable,
    *,
    verified_layout: bool = False,
) -> bool:
    try:
        equipped = _active_equipment(_single(messages), table)
    except ValueError:
        return False
    required = 4
    if verified_layout:
        required = max(2, min(4, len({item.raw_item_id for _, item in equipped})))
    grids: dict[int, set[bytes]] = defaultdict(set)
    for _, item in equipped:
        raw = item.raw_item_id.to_bytes(4, "little")
        p = portrait.find(raw)
        while p >= 0:
            grids[p % 136].add(raw)
            if len(grids[p % 136]) >= required:
                return True
            p = portrait.find(raw, p + 1)
    return False


def assemble_characters(
    frames: tuple[BDOFrame, ...],
    inventory: InventorySnapshotSummary,
    profile: CharacterLayoutProfile = NOVEMBER,
    *,
    remote_starts: set[_FrameKey],
    remote_ends: set[_FrameKey],
) -> CharacterRoster:
    layouts = profile.tables
    by_opcode = {t.opcode: name for name, t in layouts.items()}
    tables: dict[str, list[bytes]] = defaultdict(list)
    for frame in frames:
        family = by_opcode.get(frame.opcode)
        if family:
            tables[family].append(frame.message)
    warnings = []
    missing = sorted(set(NOVEMBER.tables) - set(layouts))
    if missing:
        warnings.append(
            "Character profile has no verified layout for: " + ", ".join(missing) + "."
        )
    try:
        rt = layouts["roster"]
        roster_rows = rt.rows(_single(tables["roster"]))
        off = rt.fields["owner"]
        ids = [row[off : off + 8].hex() for row in roster_rows]
        metadata_values = {
            owner: (
                _uint(row, rt.fields["metadata"], 2)
                if "metadata" in rt.fields
                else None
            )
            for owner, row in zip(ids, roster_rows)
        }
        owners = set(ids)
        if len(ids) != len(owners) or bytes(8).hex() in owners:
            raise ValueError("invalid owner IDs")
    except ValueError:
        return CharacterRoster(
            warnings=("No unique validated character roster in the selected login.",)
        )
    remote_complete = False
    try:
        pages = [f for f in frames if f.opcode == layouts["remote"].opcode]
        # The framed stream uses unwrapped TCP byte positions. A different
        # message must touch each outer edge of one uninterrupted page run.
        if not pages or any(f.stream_sequence is None for f in pages):
            raise ValueError("missing remote pages or stream positions")
        pages.sort(key=lambda f: int(f.stream_sequence or 0))
        cursor = _frame_key(pages[0])
        if cursor not in remote_starts:
            raise ValueError("first remote page not bracketed")
        for page in pages:
            if cursor != _frame_key(page) or cursor.stream_sequence is None:
                raise ValueError("gap or overlap between remote pages")
            cursor = replace(cursor, stream_sequence=cursor.stream_sequence + len(page.message))
        if cursor not in remote_ends:
            raise ValueError("last remote page not bracketed")
        sections = _remote(tables["remote"], owners, layouts["remote"])
        remote_ids = set(sections)
        remote_complete = True
    except ValueError as exc:
        sections = defaultdict(_Sections)
        # A broken remote section should not erase independently proven active
        # state. Still withhold active attribution if a readable remote row
        # explicitly claims that owner on the same connection.
        remote_ids = set()
        rt = layouts["remote"]
        for message in tables["remote"]:
            try:
                rows = rt.rows(message)
            except ValueError:
                continue
            offset = rt.fields["owner"]
            remote_ids.update(row[offset : offset + 8].hex() for row in rows)
        warnings.append(f"Remote items withheld: {exc}.")

    stats: dict[str, tuple[float, float, float]] = {}
    if tables["stats"]:
        try:
            st = layouts["stats"]
            for row in st.rows(_single(tables["stats"])):
                off = st.fields["owner"]
                owner = row[off : off + 8].hex()
                values = tuple(
                    unpack_from("<f", row, st.fields[k])[0] for k in ("dp", "ap", "aap")
                )
                if (
                    owner not in owners
                    or owner in stats
                    or not all(isfinite(x) and x >= 0 for x in values)
                ):
                    raise ValueError("invalid stats")
                stats[owner] = (values[0], values[1], values[2])
        except ValueError:
            stats.clear()
            warnings.append("Character combat stats withheld: incompatible table.")

    names: dict[str, set[str]] = defaultdict(set)
    for message in tables["named"]:
        try:
            nt = layouts["named"]
            rows = nt.rows(message)
        except ValueError:
            continue
        for row in rows:
            owner = row[nt.fields["owner"] : nt.fields["owner"] + 8].hex()
            name = _name(row[nt.fields["name"] : nt.fields["name"] + 60])
            if owner in owners and name:
                names[owner].add(name)
    # Cross-check the independently named active-character packet. Roster
    # membership or lack of a remote inventory alone cannot identify the main.
    candidates = set()
    for portrait in tables["portrait"]:
        pt = layouts["portrait"]
        try:
            (row,) = pt.rows(portrait)
        except ValueError:
            continue
        off = pt.fields["owner"]
        owner = row[off : off + 8].hex()
        if owner not in owners or owner in remote_ids:
            continue
        if "name" in pt.fields:
            off = pt.fields["name"]
            name = _name(row[off : off + 60])
            if name and names.get(owner) == {name}:
                candidates.add(owner)
            elif (
                name
                and not names.get(owner)
                and tables["active"]
                and corroborates_equipment(
                    portrait, tables["active"], layouts["active"], verified_layout=True
                )
            ):
                candidates.add(owner)
                names[owner].add(name)
        elif tables["active"]:
            # Recheck the calibrated portrait/equipment association on this login.
            if corroborates_equipment(
                portrait, tables["active"], layouts["active"], verified_layout=True
            ):
                candidates.add(owner)
    active = next(iter(candidates)) if len(candidates) == 1 else None
    if remote_complete:
        covered = remote_ids.copy()
        # A stats-only owner is safe to classify as remote only when the
        # active owner was independently identified.
        if active is not None:
            covered.update(stats.keys() - {active})
        for owner in covered:
            for section in ("main", "pearl", "gear", "other"):
                sections[owner].sources[section].add("remote")
    if active is None:
        warnings.append(
            "Active owner unresolved; active equipment, life gear and bags were not attributed."
        )
    else:
        target = sections[active]
        for stack in inventory.items:
            section = (
                {0: "main", 16: "pearl"}.get(stack.container_code, "other")
                if stack.container_code is not None
                else "other"
            )
            target.add(
                section,
                CharacterItem(
                    stack.item_id,
                    stack.quantity,
                    "active_inventory",
                    stack.inventory_slot,
                    stack.container_code,
                ),
            )
        if tables["active"]:
            try:
                equipped = _active_equipment(
                    _single(tables["active"]), layouts["active"]
                )
                for section, entry in equipped:
                    target.add(section, entry)
                target.sources["gear"].add("active_equipment")
                target.sources["life"].add("active_equipment")
            except ValueError:
                warnings.append(
                    "Active equipment withheld: incompatible or competing tables."
                )
        if tables["life"]:
            try:
                for entry in _life_equipment(_single(tables["life"]), layouts["life"]):
                    target.add("life", entry)
                target.sources["life"].add("life_equipment")
            except ValueError:
                warnings.append(
                    "Dedicated life gear withheld: incompatible or competing tables."
                )

    members = []
    for owner in ids:
        data = sections[owner]
        dp, ap, aap = stats.get(owner, (None, None, None))
        members.append(
            CharacterLoadout(
                owner_id=owner,
                name=next(iter(names[owner])) if len(names[owner]) == 1 else None,
                is_active=owner == active if active else None,
                main_inventory=data.section("main"),
                pearl_inventory=data.section("pearl"),
                gear=data.section("gear"),
                life_skills=data.section("life"),
                other_inventory=data.section("other"),
                dp=dp,
                ap=ap,
                awakening_ap=aap,
                raw_metadata_value=metadata_values[owner],
            )
        )
    return CharacterRoster(tuple(members), tuple(warnings))
