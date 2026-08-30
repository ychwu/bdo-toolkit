"""Capture a character load and print one observed town-storage destination."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.item_state import CharacterLoadSession, ItemStateSnapshot


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"
TOWN_NAME = "Heidel"


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
    status = snapshot.decoder_health.storage_status

    if status == "incompatible":
        raise RuntimeError(
            "Storage decoding is incompatible with this capture; "
            "recalibrate the profile"
        )

    storage = snapshot.storages.named(TOWN_NAME)
    if storage is None:
        raise LookupError(
            f"{TOWN_NAME} was not observed (storage decoder: {status})"
        )
    if not storage.current_state_observed:
        raise RuntimeError(
            f"{TOWN_NAME} was seen only in an earlier inferred storage sweep"
        )

    label = storage.name or f"UNKNOWN_STORAGE(0x{storage.storage_id:08x})"
    print(f"{label.upper()} CONTENTS")
    if storage.current_empty is True:
        print("explicitly observed empty")
        return

    print(f"{storage.occupied_stacks} observed occupied stacks")
    for item in storage.items:
        print(f"item_id={item.item_id} quantity={item.quantity}")

    if storage.current_identity_complete is False:
        print(
            "Warning: some current records lacked instance identity "
            "and were excluded"
        )


if __name__ == "__main__":
    main()
