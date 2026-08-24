"""Live-calibrate the optional loot-preview profile family.

Choose one known item that will appear in a gathering or loot-preview window,
then make that window appear once while this session passively captures
traffic.  The preview describes what the window offered, not proof that the
item entered inventory.

This example updates LOOT_PREVIEW only.  Existing transfer-profile families in
``opcodes.local`` remain available.
"""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit.calibration import CalibrationSession, update_profile


PROFILE = Path("opcodes.local")
ITEM_ID = 7003
ITEM_NAME = "Potato"


def main() -> None:
    session = CalibrationSession(
        item_id=ITEM_ID,
        quantity=None,
        action="loot-preview",
    )

    session.start()
    print("Listening in the background.")
    print(
        "Gather a wild potato and wait for the Item List containing "
        f"{ITEM_NAME} ({ITEM_ID})."
    )
    try:
        input(
            "After the Potato Item List appears, return here and press Enter..."
        )
    except KeyboardInterrupt:
        print()
    finally:
        print(f"collected {session.frames_collected} frames")
        result = session.stop()

    print(result.summary())
    if "LOOT_PREVIEW" not in result.events_found:
        raise SystemExit(
            "loot preview was not calibrated; confirm the raw item ID, start "
            "capture before gathering, and try one clean preview again"
        )

    update = update_profile(
        result,
        PROFILE,
        action="loot-preview",
    )
    print(update.summary())


if __name__ == "__main__":
    main()
