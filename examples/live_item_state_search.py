"""Find one exact item ID across observed inventory and town storage."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.item_state import CharacterLoadSession, ItemStateSnapshot


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"
TARGET_ITEM_ID = 7003
TARGET_LABEL = "Potato"


def capture_snapshot() -> ItemStateSnapshot:
    if not PROFILE.is_file():
        raise FileNotFoundError(
            f"opcode profile not found: {PROFILE}; fetch or calibrate it first"
        )

    session = CharacterLoadSession(opcode_profile=PROFILE)
    print(f"Using opcode profile: {PROFILE}", flush=True)
    session.start()

    try:
        input(
            "Capture started. Open the game or switch characters, wait until "
            "the playable world has settled, then press Enter to continue.\n"
        )
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        snapshot = session.stop()

    return snapshot


def main() -> None:
    snapshot = capture_snapshot()
    if not snapshot.hydration_detected:
        raise RuntimeError("No character-load item state was detected")

    print(f"{TARGET_LABEL} (item_id={TARGET_ITEM_ID})")
    inventory_total: int | None = None
    if snapshot.inventory.hydration_observed:
        inventory_total = snapshot.inventory.quantity_for(TARGET_ITEM_ID)
        print(f"Character inventory: {inventory_total}")
    else:
        print("Character inventory: unavailable (not observed)")

    storage_total: int | None = None
    storage_status = snapshot.decoder_health.storage_status
    if storage_status == "compatible":
        storage_total = snapshot.storages.total_quantity(TARGET_ITEM_ID)
        print(f"Town storage: {storage_total}")
        for storage in snapshot.storages.locations_for(TARGET_ITEM_ID):
            label = storage.name or (
                f"UNKNOWN_STORAGE(0x{storage.storage_id:08x})"
            )
            print(f"  {label}: {storage.quantity_for(TARGET_ITEM_ID)}")
    else:
        print(f"Town storage: unavailable (decoder status: {storage_status})")

    if inventory_total is not None and storage_total is not None:
        print(f"Observed total: {inventory_total + storage_total}")

    if (
        snapshot.inventory.hydration_observed
        and snapshot.coverage.inventory_records_missing_instance
    ):
        print(
            "Warning: some inventory records were excluded "
            "because identity was missing"
        )
    if (
        storage_total is not None
        and snapshot.coverage.selected_storage_records_missing_instance
    ):
        print(
            "Warning: some selected storage records were excluded "
            "because identity was missing"
        )
    if storage_total is not None and snapshot.coverage.storage_locations_not_selected:
        print(
            "Warning: some earlier-observed towns were not revisited "
            "in the selected storage sweep"
        )
    missing = snapshot.coverage.registered_storage_ids_not_observed
    if storage_total is not None and missing:
        print(
            f"Warning: {len(missing)} registered storage destinations "
            "were not observed"
        )


if __name__ == "__main__":
    main()
