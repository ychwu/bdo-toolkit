"""Run interactive live calibration from an asyncio application."""

from __future__ import annotations

import asyncio
from pathlib import Path

from bdo_toolkit import AsyncCalibrationSession
from bdo_toolkit.calibration import update_profile


PROFILE = Path("opcodes.local")
ITEM_ID = 7003
QUANTITY = 5


async def main() -> None:
    async with AsyncCalibrationSession(
        item_id=ITEM_ID,
        quantity=QUANTITY,
    ) as session:
        print(f"Move exactly {QUANTITY} of item {ITEM_ID} to storage and back.")
        # A real async app would await its own Done button/event instead.
        await asyncio.to_thread(input, "Press Enter when both moves are done...")
        print(f"collected {session.frames_collected} frames")
        result = await session.stop()

    print(result.summary())
    if not result.specs:
        raise SystemExit(1)

    update = await asyncio.to_thread(
        update_profile,
        result,
        PROFILE,
        replace=True,
    )
    print(update.summary())


if __name__ == "__main__":
    asyncio.run(main())
