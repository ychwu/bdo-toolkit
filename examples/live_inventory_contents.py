"""Capture a character load and print observed ordinary inventory stacks."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.item_state import CharacterLoadSession, ItemStateSnapshot


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"


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
    inventory = snapshot.inventory

    if not inventory.groups:
        raise RuntimeError("No character-inventory snapshot was observed")

    print("INVENTORY CONTENTS")
    print(f"{inventory.occupied_stacks} observed occupied stacks")
    for item in inventory.items:
        container = item.container_name or "Unclassified"
        print(
            f"item_id={item.item_id} "
            f"quantity={item.quantity} "
            f"container_label={container}"
        )

    if not inventory.identity_complete:
        print(
            "Warning: some inventory records lacked instance identity "
            "and were excluded"
        )


if __name__ == "__main__":
    main()
