"""Consume live events without blocking an asyncio application.

Press Enter to stand in for an async application's Stop control.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from bdo_toolkit import AsyncLiveCaptureSession, EventFilter


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"


async def print_events(session: AsyncLiveCaptureSession) -> None:
    async for event in session:
        print(event.format_human())


async def main() -> None:
    if not PROFILE.is_file():
        raise FileNotFoundError(f"calibrated opcode profile not found: {PROFILE}")

    async with AsyncLiveCaptureSession(
        opcode_profile=PROFILE,
        event_filter=EventFilter(
            event_types={"item_received", "storage_delta"},
        ),
    ) as session:
        consumer = asyncio.create_task(print_events(session))
        try:
            # A real async app would await its own button/event instead.
            await asyncio.to_thread(input, "Capture started. Press Enter to stop.\n")
        finally:
            await session.stop()
            # stop() finalizes capture; the consumer drains those final events.
            await consumer

    print("stopped:", session.stopped)
    print("reason:", session.stop_reason)


if __name__ == "__main__":
    asyncio.run(main())
