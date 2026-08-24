"""Run one three-action live calibration from an asyncio application.

Deposit one matching unstackable, deposit the remaining four, then withdraw
all five before finishing the session. These are user-performed actions while
the session passively captures traffic.

This example updates transfer-profile families only; it does not calibrate
LOOT_PREVIEW. Default profile updates preserve unrelated existing families.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from bdo_toolkit import AsyncCalibrationSession
from bdo_toolkit.calibration import update_profile


PROFILE = Path("opcodes.local")
ITEM_ID = 15156  # Matching unstackable calibration item selected for this run.
# Expected in each serialized item record. A four-item action produces four
# matching records whose quantity is 1; this does not automate the in-game move.
QUANTITY = 1


async def main() -> None:
    async with AsyncCalibrationSession(
        item_id=ITEM_ID,
        quantity=QUANTITY,
    ) as session:
        print("Listening in the background.")
        print(
            "Perform the following in-game actions yourself while capture remains open."
        )
        print(
            "Use one unambiguous town such as Velia, Heidel, Calpheon City, or Olvia."
        )
        print("Do not use Muzgar, Velandir, Yukjo Street, Godu Village, or Bukpo.")
        print(f"Using unstackable item {ITEM_ID} (record quantity {QUANTITY}):")
        print("deposit one item, then deposit the remaining four,")
        print("then withdraw all five matching items in one action.")
        # A real async app would await its own Done button/event instead.
        await asyncio.to_thread(input, "Press Enter when all three moves are done...")
        print(f"collected {session.frames_collected} frames")
        result = await session.stop()

    print(result.summary())
    required = {
        "INVENTORY_TRANSFER",
        "SOURCE_STACK_DECREMENT",
        "STORAGE_ITEM_DELTA",
    }
    missing = sorted(required - result.events_found)
    if missing:
        raise SystemExit(
            "incomplete transfer profile; missing "
            f"{', '.join(missing)}. Rerun one clean session: deposit 1, "
            "deposit the remaining 4, then withdraw all 5."
        )

    update = await asyncio.to_thread(
        update_profile,
        result,
        PROFILE,
    )
    print(update.summary())


if __name__ == "__main__":
    asyncio.run(main())
