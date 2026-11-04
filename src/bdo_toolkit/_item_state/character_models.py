"""Typed experimental character inventories observed during one login."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class CharacterItem:
    """One item in a source-specific raw slot, with any embedded lightstones."""

    raw_item_id: int
    quantity: int
    source: str
    raw_slot: int | None
    raw_container: int | None = None
    role: str | None = None
    activity: str | None = None
    # Tuple positions preserve sockets, including an unoccupied first socket.
    lightstones: tuple[int | None, ...] = ()
    role_inferred: bool = False

    @property
    def base_item_id(self) -> int:
        return self.raw_item_id & 0xFFFFFF

    def to_dict(self) -> dict[str, object]:
        return {
            **asdict(self),
            "base_item_id": self.base_item_id,
            "lightstones": list(self.lightstones),
        }


@dataclass(frozen=True)
class CharacterSection:
    """An available section can replace saved items, including with zero rows."""

    items: tuple[CharacterItem, ...] = ()
    observed_sources: tuple[str, ...] = ()
    complete: bool = True

    @property
    def observed(self) -> bool:
        return self.complete and bool(self.observed_sources)

    @property
    def status(self) -> str:
        return "available" if self.observed else "unavailable"

    def for_activity(self, activity: str) -> tuple[CharacterItem, ...]:
        return tuple(item for item in self.items if item.activity == activity)

    def by_role(
        self, role: str, *, activity: str | None = None
    ) -> tuple[CharacterItem, ...]:
        """Return observed occupants, optionally scoped to one life activity."""
        return tuple(
            item
            for item in self.items
            if item.role == role and (activity is None or item.activity == activity)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "observed": self.observed,
            "observed_sources": list(self.observed_sources),
            "items": [item.to_dict() for item in self.items],
        }


@dataclass(frozen=True)
class CharacterLoadout:
    owner_id: str
    name: str | None
    is_active: bool | None
    main_inventory: CharacterSection
    pearl_inventory: CharacterSection
    gear: CharacterSection
    life_skills: CharacterSection
    other_inventory: CharacterSection
    dp: float | None = None
    ap: float | None = None
    awakening_ap: float | None = None
    character_class: str | None = None
    level: int | None = None
    raw_metadata_value: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "owner_id": self.owner_id,
            "name": self.name,
            "is_active": self.is_active,
            "character_class": self.character_class,
            "level": self.level,
            "raw_metadata_value": self.raw_metadata_value,
            "dp": self.dp,
            "ap": self.ap,
            "awakening_ap": self.awakening_ap,
            "main_inventory": self.main_inventory.to_dict(),
            "pearl_inventory": self.pearl_inventory.to_dict(),
            "gear": self.gear.to_dict(),
            "life_skills": self.life_skills.to_dict(),
            "other_inventory": self.other_inventory.to_dict(),
        }


@dataclass(frozen=True)
class CharacterRoster:
    members: tuple[CharacterLoadout, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        return "available" if self.members else "unavailable"

    def by_id(self, owner_id: str) -> CharacterLoadout | None:
        return next(
            (member for member in self.members if member.owner_id == owner_id), None
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "by_id": {member.owner_id: member.to_dict() for member in self.members},
            "warnings": list(self.warnings),
        }
