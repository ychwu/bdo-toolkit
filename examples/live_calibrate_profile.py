"""Live-calibrate a local opcode profile with explicit start/stop."""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.calibration import CalibrationSession, update_profile


PROFILE = Path("opcodes.local")


def main() -> None:
    session = CalibrationSession(
        item_id=7003,
        quantity=3,
        action="inventory-to-storage",
    )

    session.start()
    print("Listening in the background.")
    print("Move exactly 3 Potatoes from inventory to storage once.")
    try:
        input("Press Enter when the action is done...")
    except KeyboardInterrupt:
        print()
    finally:
        print(f"collected {session.frames_collected} frames")
        result = session.stop()

    print(f"scanned {result.frames_scanned} frames")
    if not result.specs:
        raise SystemExit("no opcode specs discovered")

    for spec in result.specs:
        fields = spec.to_json_dict()
        print(
            f"{fields['event']} "
            f"opcode={fields['opcode']} "
            f"length={fields['length']}"
        )

    update = update_profile(
        result,
        PROFILE,
        action="inventory-to-storage",
        replace=True,
    )
    print(f"wrote {update.path}")
    if update.backup_path is not None:
        print(f"backup at {update.backup_path}")


if __name__ == "__main__":
    main()
