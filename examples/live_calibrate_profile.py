"""Live-calibrate a local opcode profile with explicit start/stop.

Auto calibration detects both transfer directions from packet structure, so
you just move an item to storage and back -- no need to declare which action
is which.
"""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.calibration import CalibrationSession, update_profile


PROFILE = Path("opcodes.local")
ITEM_ID = 7003  # Potato Test
QUANTITY = 5


def main() -> None:
    session = CalibrationSession(item_id=ITEM_ID, quantity=QUANTITY)

    session.start()
    print("Listening in the background.")
    print(f"Move exactly {QUANTITY} of item {ITEM_ID} from storage to inventory,")
    print("then back to storage (either order).")
    try:
        input("Press Enter when both moves are done...")
    except KeyboardInterrupt:
        print()
    finally:
        print(f"collected {session.frames_collected} frames")
        result = session.stop()

    print(f"scanned {result.frames_scanned} frames")

    detected = sorted(
        {
            "storage->inventory" if e.detected_family == "into_inventory"
            else "inventory->storage"
            for e in result.evidence
            if e.detected_family is not None
        }
    )
    if detected:
        print("detected direction(s):", ", ".join(detected))

    if not result.specs:
        raise SystemExit("no opcode specs discovered")

    for spec in result.specs:
        fields = spec.to_json_dict()
        print(f"{fields['event']} opcode={fields['opcode']} length={fields['length']}")

    update = update_profile(result, PROFILE, replace=True)
    print(f"wrote {update.path}")
    if update.backup_path is not None:
        print(f"backup at {update.backup_path}")


if __name__ == "__main__":
    main()
