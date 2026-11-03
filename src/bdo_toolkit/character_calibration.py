"""Passive calibration of character-layout sidecars from a normal world login."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
import math

from ._capture_options import LiveCaptureOptions
from ._protocol import DEFAULT_SERVER_PORTS
from ._item_state.character_profile import (
    CharacterLayoutProfile,
    CharacterTable,
    NOVEMBER,
)
from ._item_state.character_discovery import discover_core
from ._item_state.character_witnesses import (
    Witnesses,
    reference_witnesses,
    active_layouts,
    life_layout,
    remote_sockets,
    stats_layout,
)
from .raw import LiveRawSession, RawMessage, replay_raw

_MAX_MESSAGES = 30000
_MAX_BYTES = 96 * 1024 * 1024


@dataclass(frozen=True)
class CharacterCalibrationResult:
    profile: CharacterLayoutProfile | None
    families: dict[str, str]
    messages_observed: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "usable": self.profile is not None,
            "messages_observed": self.messages_observed,
            "reason": self.reason,
            "families": dict(self.families),
            "profile": self.profile.to_dict() if self.profile else None,
        }


def _frames(stream: Iterable[RawMessage]) -> list[RawMessage]:
    frames: list[RawMessage] = []
    size = 0
    for f in stream:
        size += len(f.message)
        if len(frames) >= _MAX_MESSAGES or size > _MAX_BYTES:
            raise ValueError("character calibration capture limit exceeded")
        frames.append(f)
    return frames


def _previous(
    value: CharacterLayoutProfile | str | Path | None,
) -> CharacterLayoutProfile:
    if isinstance(value, CharacterLayoutProfile):
        return value
    return CharacterLayoutProfile.load(value) if value is not None else NOVEMBER


def _references(
    path: str | Path | None, previous: CharacterLayoutProfile, ports: tuple[int, ...]
) -> Witnesses:
    if path is None:
        return Witnesses()
    with replay_raw(path, ports=ports) as stream:
        frames = _frames(stream)
    # Refuse a mismatched or mixed reference rather than silently training
    # against different owners/eras. A reference is a single normal login.
    roster = previous.tables["roster"]
    rosters = [f for f in frames if f.opcode == roster.opcode]
    if len(rosters) != 1 or not roster.rows(rosters[0].message):
        raise ValueError("reference does not match previous roster layout")
    anchor = rosters[0]
    return reference_witnesses(
        [
            f
            for f in frames
            if f.flow == anchor.flow
            and f.connection_epoch == anchor.connection_epoch
            and abs(f.observed_at - anchor.observed_at) <= 30
        ],
        previous,
    )


def _calibrate(
    frames: list[RawMessage],
    previous: CharacterLayoutProfile,
    refs: Witnesses,
) -> CharacterCalibrationResult:
    state = {family: "unavailable" for family in NOVEMBER.tables}
    candidates = discover_core(frames, previous)
    if len(candidates) != 1:
        reason = (
            "Insufficient corroborated owner tables."
            if not candidates
            else "Competing remote layouts or load epochs."
        )
        return CharacterCalibrationResult(None, state, len(frames), reason)
    core = candidates[0]
    tables = {"remote": remote_sockets(core, refs), "roster": core.roster}
    stats = stats_layout(core, previous, refs)
    life = life_layout(core, previous, refs)
    if stats:
        tables["stats"] = stats
    if life:
        tables["life"] = life
    tables.update(active_layouts(core, previous))
    conflicts = {
        family
        for family, table in tables.items()
        if family not in ("remote", "roster")
        and any(
            other != family and tab.opcode == table.opcode
            for other, tab in tables.items()
        )
    }
    for family in conflicts:
        state[family] = "ambiguous"
        del tables[family]
    profile = CharacterLayoutProfile(tables)
    for family, table in tables.items():
        state[family] = (
            "revalidated" if table == previous.tables.get(family) else "discovered"
        )
    state["remote_lightstones"] = (
        ("reference_matched" if refs.stones else "structurally_inferred")
        if "stone1" in tables["remote"].fields
        else "unavailable"
    )
    return CharacterCalibrationResult(
        profile,
        state,
        len(frames),
        f"Unique remote layout across {len(core.chunk.rows)} records and independently corroborated owner tables.",
    )


def calibrate_character_layout_pcap(
    path: str | Path,
    *,
    previous_profile: CharacterLayoutProfile | str | Path | None = None,
    reference_pcap: str | Path | None = None,
    ports: tuple[int, ...] = DEFAULT_SERVER_PORTS,
) -> CharacterCalibrationResult:
    previous = _previous(previous_profile)
    refs = _references(reference_pcap, previous, ports)
    with replay_raw(path, ports=ports) as stream:
        frames = _frames(stream)
    return _calibrate(frames, previous, refs)


def calibrate_character_layout_live(
    *,
    capture_seconds: float = 120,
    live_options: LiveCaptureOptions | None = None,
    save_pcap: str | Path | None = None,
    on_ready: Callable[[], None] | None = None,
    previous_profile: CharacterLayoutProfile | str | Path | None = None,
    reference_pcap: str | Path | None = None,
) -> CharacterCalibrationResult:
    """Capture one login directly. No item opcode profile or intermediate replay required."""
    if not math.isfinite(capture_seconds) or capture_seconds <= 0:
        raise ValueError("capture_seconds must be positive and finite")
    previous = _previous(previous_profile)
    refs = _references(
        reference_pcap,
        previous,
        live_options.ports if live_options else DEFAULT_SERVER_PORTS,
    )
    with LiveRawSession(
        live_options=live_options, capture_seconds=capture_seconds, save_pcap=save_pcap
    ) as session:
        if on_ready is not None:
            on_ready()
        frames = _frames(session.events())
    if session.error:
        raise session.error
    return _calibrate(frames, previous, refs)
