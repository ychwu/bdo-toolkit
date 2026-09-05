"""Private calibration persistence implementation."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Optional
from .._profile_io import (
    atomic_write_text as _atomic_write_text,
    next_backup_path as _backup_path,
)
from .._specs import _validate_loot_profile_entries
from ..profiles import (
    OPCODE_PROFILE_SCHEMA_VERSION,
    ProfileError,
    _validate_profile_entry,
    load_opcode_profile,
)
from ._constants import CALIBRATION_ACTIONS, OPCODE_PROFILE_EVENTS
from ._formatting import _events_for_action, _utc_now_text
from .models import (
    CalibrationAuthorityError,
    CalibrationResult,
    MessageSpec,
    ProfileUpdate,
)
from .validation import _validate_profile_replacement_options


def update_profile(
    result: CalibrationResult | Iterable[MessageSpec],
    path: str | Path,
    *,
    action: str = "auto",
    replace: bool = True,
    replace_entire_action: bool = False,
    backup: bool = True,
    calibration_item_id: Optional[int] = None,
) -> ProfileUpdate:
    """Persist promoted specs into a local opcode profile file.

    By default, only the event families represented by the supplied specs are
    cleared first.  Explicit-action and raw-spec callers can therefore apply a
    reviewed partial update without erasing unrelated evidence. Automatic
    transfer results must contain every runtime-required transfer family.
    Pass ``replace_entire_action=True`` for an explicit reset of every family
    belonging to ``action``. Pass ``replace=False`` only for an intentional
    advanced merge that preserves and deduplicates existing specs. The
    previous file is backed up next to it unless ``backup=False``.
    """
    if action != "auto" and action not in CALIBRATION_ACTIONS:
        raise ValueError(
            f"unknown calibration action {action!r}; "
            f"expected one of {CALIBRATION_ACTIONS} or 'auto'"
        )
    if isinstance(result, CalibrationResult):
        from_calibration_result = True
        specs = tuple(result.specs)
        if calibration_item_id is None:
            calibration_item_id = result.calibration_item_id
    else:
        from_calibration_result = False
        specs = tuple(result)
    if any(not isinstance(spec, MessageSpec) for spec in specs):
        raise TypeError("update_profile expects MessageSpec objects")
    _validate_profile_replacement_options(replace, replace_entire_action)
    if from_calibration_result and action == "auto" and specs:
        transfer_events = {
            "INVENTORY_TRANSFER",
            "SOURCE_CONTAINER_DECREMENT",
            "SOURCE_STACK_DECREMENT",
            "SOURCE_ITEM_REFERENCE",
            "STORAGE_ITEM_DELTA",
        }
        observed_events = {spec.event for spec in specs}
        if observed_events & transfer_events:
            required = {
                "INVENTORY_TRANSFER",
                "SOURCE_STACK_DECREMENT",
                "STORAGE_ITEM_DELTA",
            }
            missing = sorted(required - observed_events)
            if missing:
                raise CalibrationAuthorityError(
                    "auto calibration is incomplete and cannot safely replace a "
                    "post-patch profile; missing required runtime family/families: "
                    f"{', '.join(missing)}. Capture the complete guided transfer "
                    "sequence so both directions and the source-stack decrement "
                    "are observed, including an unstackable multi-record deposit, "
                    "or pass the matching explicit action only for an intentional "
                    "reviewed partial update. No profile was written."
                )
    profile_path = Path(path)
    if not specs:
        return ProfileUpdate(
            path=profile_path,
            added=(),
            replaced_events=(),
            backup_path=None,
            written=False,
        )
    if calibration_item_id is not None and (
        isinstance(calibration_item_id, bool)
        or not isinstance(calibration_item_id, int)
        or not 1 <= calibration_item_id <= 0xFFFFFFFF
    ):
        raise ValueError("calibration_item_id must be None or a positive uint32")
    data = _load_profile_data(profile_path)

    replaced_events: tuple[str, ...] = ()
    if replace and specs:
        replacement_scope = (
            _events_for_action(action)
            if replace_entire_action
            else tuple(dict.fromkeys(spec.event for spec in specs))
        )
        removed_events: list[str] = []
        for event in replacement_scope:
            if data["specs"].get(event):
                removed_events.append(event)
            data["specs"][event] = []
        replaced_events = tuple(removed_events)

    existing_keys = _profile_dedupe_keys(data)
    added: list[MessageSpec] = []
    for spec in specs:
        key = spec.dedupe_key()
        if key in existing_keys:
            continue
        data["specs"].setdefault(spec.event, [])
        data["specs"][spec.event].append(spec.to_json_dict())
        existing_keys.add(key)
        added.append(spec)

    if not added and not replaced_events:
        return ProfileUpdate(
            path=profile_path,
            added=(),
            replaced_events=(),
            backup_path=None,
            written=False,
        )

    # Reject a LOOT merge that would make runtime layout selection impossible
    # before creating a backup or replacing the destination file. Other
    # calibration families may intentionally persist partial evidence that is
    # not yet a runtime-decodable spec.
    _validate_loot_profile_entries(
        data["specs"].get("LOOT_PREVIEW", ()),
        source=profile_path,
    )

    data["profile_active"] = True
    data["updated_at"] = _utc_now_text()
    if calibration_item_id is not None:
        data["calibration_item_id"] = calibration_item_id

    backup_path = None
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    if backup and profile_path.exists():
        backup_path = _backup_path(profile_path)
        shutil.copy2(profile_path, backup_path)

    _atomic_write_text(
        profile_path,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
    )

    return ProfileUpdate(
        path=profile_path,
        added=tuple(added),
        replaced_events=replaced_events,
        backup_path=backup_path,
    )


def reset_profile(
    path: str | Path,
    calibration_item_id: int = 15156,
    *,
    backup: bool = True,
) -> Optional[Path]:
    """Write an empty active profile, returning the backup path if any.

    ``calibration_item_id`` is maintenance metadata only. The default names the
    recommended unstackable calibration item and remains explicitly
    overrideable; resetting a profile does not itself calibrate that item.
    """
    if (
        isinstance(calibration_item_id, bool)
        or not isinstance(calibration_item_id, int)
        or not 1 <= calibration_item_id <= 0xFFFFFFFF
    ):
        raise ValueError("calibration_item_id must be a positive uint32")
    profile_path = Path(path)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = None
    if backup and profile_path.exists():
        backup_path = _backup_path(profile_path)
        shutil.copy2(profile_path, backup_path)

    data = {
        "version": OPCODE_PROFILE_SCHEMA_VERSION,
        "updated_at": _utc_now_text(),
        "calibration_item_id": calibration_item_id,
        "profile_active": True,
        "specs": {event: [] for event in OPCODE_PROFILE_EVENTS},
    }
    _atomic_write_text(
        profile_path,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
    )
    return backup_path


def _load_profile_data(path: Path) -> dict[str, Any]:
    if path.exists():
        # Validate every supported top-level section, including explicitly
        # promoted origin companion families, before preserving the file.
        load_opcode_profile(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ProfileError(f"Could not parse opcodes JSON {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ProfileError(f"Opcodes JSON {path} must be a top-level object")
    else:
        data = {"version": OPCODE_PROFILE_SCHEMA_VERSION}

    version = data.get("version")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != OPCODE_PROFILE_SCHEMA_VERSION
    ):
        raise ProfileError(
            f"version in {path} must be {OPCODE_PROFILE_SCHEMA_VERSION}"
        )
    active = data.get("profile_active", False)
    if not isinstance(active, bool):
        raise ProfileError(f"profile_active in {path} must be a boolean")
    updated_at = data.get("updated_at")
    if updated_at is not None and not isinstance(updated_at, str):
        raise ProfileError(f"updated_at in {path} must be a string")
    calibration_item_id = data.get("calibration_item_id")
    if calibration_item_id is not None and (
        isinstance(calibration_item_id, bool)
        or not isinstance(calibration_item_id, int)
        or not 1 <= calibration_item_id <= 0xFFFFFFFF
    ):
        raise ProfileError(
            f"calibration_item_id in {path} must be a positive uint32"
        )

    specs = data.get("specs", {})
    if not isinstance(specs, dict):
        raise ProfileError(f"specs in {path} must be an object")
    for event, entries in specs.items():
        if not isinstance(event, str):
            raise ProfileError(f"spec event names in {path} must be strings")
        if not isinstance(entries, list):
            raise ProfileError(f"specs[{event!r}] in {path} must be a list")
        if any(not isinstance(entry, dict) for entry in entries):
            raise ProfileError(
                f"every specs[{event!r}] entry in {path} must be an object"
            )
        for index, entry in enumerate(entries):
            _validate_profile_entry(path, event, index, entry)
    for event in OPCODE_PROFILE_EVENTS:
        specs.setdefault(event, [])

    data["version"] = version
    data["profile_active"] = active
    data["specs"] = specs
    data.setdefault("updated_at", _utc_now_text())
    return data


def _profile_dedupe_keys(data: dict[str, Any]) -> set[tuple[object, ...]]:
    specs = data.get("specs", {})
    if not isinstance(specs, dict):
        return set()

    keys: set[tuple[object, ...]] = set()
    for event, entries in specs.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            opcode = _profile_opcode(entry.get("opcode"), event)
            keys.add(
                (
                    event,
                    opcode,
                    entry.get("length"),
                    entry.get("item_id_offset"),
                    entry.get("quantity_offset"),
                    entry.get("item_instance_offset"),
                    entry.get("context_offset"),
                    entry.get("record_count_offset"),
                    entry.get("inventory_slot_offset"),
                    entry.get("source_instance_offset"),
                    entry.get("quantity_removed_offset"),
                    entry.get("quantity_added_offset"),
                    entry.get("destination_instance_offset"),
                    entry.get("repeat_stride"),
                )
            )
    return keys


def _profile_opcode(value: object, event: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"invalid opcode for {event}: {value!r}")
    if isinstance(value, int):
        opcode = value
    elif isinstance(value, str):
        try:
            opcode = int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError as exc:
            raise ProfileError(f"invalid opcode for {event}: {value!r}") from exc
    else:
        raise ProfileError(f"invalid opcode for {event}: {value!r}")
    if not 0 <= opcode <= 0xFFFF:
        raise ProfileError(f"opcode for {event} must be a uint16")
    return opcode
