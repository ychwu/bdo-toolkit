"""Versioned character-layout sidecars. Files contain geometry, never account data."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
import os
import tempfile

# Required fields with byte widths, then optional fields.
_FIELDS = {
    "roster": ({"owner": 8}, {"metadata": 2}),
    "remote": (
        {"owner": 8, "container": 1, "slot": 1, "item": 4, "quantity": 8},
        {"stone1": 4, "stone2": 4},
    ),
    "stats": ({"owner": 8, "dp": 4, "ap": 4, "aap": 4}, {}),
    "named": ({"owner": 8, "name": 60}, {}),
    "portrait": ({"owner": 8}, {"name": 60}),
    "active": ({"item": 4, "quantity": 8}, {"stone1": 4, "stone2": 4}),
    "life": ({"item": 4, "quantity": 8, "slot": 1}, {"stone1": 4, "stone2": 4}),
}


@dataclass(frozen=True)
class CharacterTable:
    opcode: int
    header: int
    stride: int
    count_offset: int | None
    fixed_count: int | None
    fields: Mapping[str, int]

    def __post_init__(self) -> None:
        if any(type(v) is not int for v in (self.opcode, self.header, self.stride)):
            raise ValueError("invalid character table geometry")
        if not (
            0 <= self.opcode <= 65535
            and 0 <= self.header <= 65535
            and 1 <= self.stride <= 65535
        ):
            raise ValueError("character table geometry out of range")
        if (self.count_offset is None) == (self.fixed_count is None):
            raise ValueError("choose counted or fixed table geometry")
        if self.count_offset is not None and (
            type(self.count_offset) is not int
            or not 0 <= self.count_offset <= self.header - 2
        ):
            raise ValueError("invalid count offset")
        if self.fixed_count is not None and (
            type(self.fixed_count) is not int
            or self.fixed_count < 1
            or self.header + self.stride * self.fixed_count > 65535
        ):
            raise ValueError("invalid fixed table size")
        if not isinstance(self.fields, Mapping) or any(
            type(x) is not int or not 0 <= x < self.stride for x in self.fields.values()
        ):
            raise ValueError("invalid field offset")
        object.__setattr__(self, "fields", MappingProxyType(dict(self.fields)))

    def rows(self, message: bytes) -> list[bytes]:
        n = self.fixed_count
        if self.count_offset is not None:
            n = int.from_bytes(
                message[self.count_offset : self.count_offset + 2], "little"
            )
        if n is None or len(message) != self.header + n * self.stride:
            raise ValueError("incompatible character wrapper geometry")
        return [
            message[i : i + self.stride]
            for i in range(self.header, len(message), self.stride)
        ]

    def to_dict(self) -> dict[str, object]:
        return dict(
            opcode=self.opcode,
            header=self.header,
            stride=self.stride,
            count_offset=self.count_offset,
            fixed_count=self.fixed_count,
            fields=dict(self.fields),
        )


@dataclass(frozen=True)
class CharacterLayoutProfile:
    tables: Mapping[str, CharacterTable]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.tables, Mapping)
            or not {"remote", "roster"} <= self.tables.keys()
        ):
            raise ValueError("character profile requires remote and roster tables")
        opcodes = set()
        for family, table in self.tables.items():
            if (
                family not in _FIELDS
                or not isinstance(table, CharacterTable)
                or table.opcode in opcodes
            ):
                raise ValueError("unknown or duplicate character packet family")
            opcodes.add(table.opcode)
            required, optional = _FIELDS[family]
            widths = {**required, **optional}
            if not required.keys() <= table.fields.keys() <= widths.keys():
                raise ValueError(f"invalid fields for {family}")
            used: set[int] = set()
            for field, pos in table.fields.items():
                span = set(range(pos, pos + widths[field]))
                if pos + widths[field] > table.stride or span & used:
                    raise ValueError(f"invalid {family}.{field} span")
                used.update(span)
            if ("stone1" in table.fields) != ("stone2" in table.fields):
                raise ValueError("incomplete lightstone layout")
            if (family in ("active", "portrait")) != (table.fixed_count is not None):
                raise ValueError("incorrect table kind")
            if family == "portrait" and table.fixed_count != 1:
                raise ValueError("portrait must be a single record")
        object.__setattr__(self, "tables", MappingProxyType(dict(self.tables)))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "tables": {k: v.to_dict() for k, v in self.tables.items()},
        }

    @classmethod
    def load(cls, path: str | Path) -> CharacterLayoutProfile:
        with Path(path).open("rb") as file:
            raw = file.read(65537)
        if len(raw) > 65536:
            raise ValueError("character layout file exceeds 64 KiB")
        data = json.loads(raw.decode("utf-8-sig"))
        if (
            not isinstance(data, dict)
            or set(data) != {"schema_version", "tables"}
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or not isinstance(data["tables"], dict)
        ):
            raise ValueError("unsupported character layout profile")
        try:
            return cls({k: CharacterTable(**v) for k, v in data["tables"].items()})
        except TypeError as exc:
            raise ValueError("invalid character layout profile") from exc

    def save(self, path: str | Path, *, overwrite: bool = False) -> None:
        target = Path(path)
        if overwrite and target.exists():
            CharacterLayoutProfile.load(target)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            tmp_path.write_text(
                json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8"
            )
            if overwrite:
                os.replace(tmp_path, target)
            else:
                os.link(tmp_path, target)
        finally:
            tmp_path.unlink(missing_ok=True)


T = CharacterTable
NOVEMBER = CharacterLayoutProfile(
    {
        "roster": T(0x160C, 7, 10, 5, None, {"owner": 2, "metadata": 0}),
        "remote": T(
            0x1543,
            14,
            73,
            8,
            None,
            {
                "owner": 64,
                "container": 72,
                "slot": 42,
                "item": 60,
                "quantity": 4,
                "stone1": 26,
                "stone2": 30,
            },
        ),
        "stats": T(
            0x134C, 10, 24, 8, None, {"owner": 0, "dp": 12, "ap": 16, "aap": 20}
        ),
        "named": T(0x15EC, 7, 269, 5, None, {"owner": 21, "name": 113}),
        "portrait": T(0xD36, 0, 8073, None, 1, {"owner": 2983, "name": 7007}),
        "active": T(
            0xEA0,
            13,
            221,
            None,
            46,
            {"item": 0, "quantity": 4, "stone1": 168, "stone2": 172},
        ),
        "life": T(
            0xE9E,
            10,
            223,
            5,
            None,
            {"item": 0, "quantity": 4, "slot": 221, "stone1": 168, "stone2": 172},
        ),
    }
)
