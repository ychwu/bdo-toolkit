"""Async automatic calibration with progress marshalled to the event loop.

Passively observes deposit 1 / deposit 4 / withdraw 5. Writes only the finalized
transfer profile, keeping a backup and unrelated families. Cancellation exits
the context and skips the write.
"""

import asyncio
from pathlib import Path

from bdo_toolkit import AsyncCalibrationSession
from bdo_toolkit.calibration import CalibrationProgress, update_profile


PROFILE = Path("opcodes.local")
ITEM_ID = 15156


def show_progress(update: CalibrationProgress) -> None:
    # Runs on the event loop: replace the display, never union candidate specs.
    found = ", ".join(f"{s.event}=0x{s.opcode:04X}" for s in update.specs)
    print(f"{update.kind}: {found or 'waiting for evidence'}", flush=True)


async def main() -> None:
    loop = asyncio.get_running_loop()
    async with AsyncCalibrationSession(
        item_id=ITEM_ID, quantity=1, stop_on_complete=True,
        on_update=lambda update: loop.call_soon_threadsafe(show_progress, update),
    ) as session:
        print("Listening. In Velia or Heidel, deposit 1, deposit 4, then withdraw all 5.")
        result = await session.wait()
        assert result is not None
    print(result.summary())
    print((await asyncio.to_thread(update_profile, result, PROFILE)).summary())


if __name__ == "__main__":
    asyncio.run(main())
