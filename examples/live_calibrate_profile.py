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

    print(result.summary())
    if not result.specs:
        raise SystemExit(1)

    update = update_profile(result, PROFILE, replace=True)
    print(update.summary())


if __name__ == "__main__":
    main()
