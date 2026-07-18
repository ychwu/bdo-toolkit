"""Live listener: print every detected item transfer/storage action.

The event filter intentionally excludes ``inventory_snapshot`` and
``storage_snapshot`` records emitted while existing character state hydrates.
"""

from __future__ import annotations

from pathlib import Path

from bdo_toolkit import ConsoleEventWriter, EventFilter, capture_live


def main() -> None:
    writer = ConsoleEventWriter()
    local_profile = Path(__file__).resolve().parents[1] / "opcodes.local"
    if not local_profile.is_file():
        raise FileNotFoundError(f"calibrated opcode profile not found: {local_profile}")
    print(f"Using opcode profile: {local_profile}", flush=True)
    for event in capture_live(
        opcode_profile=local_profile,
        # Keep live deltas/transfers; omit character-state hydration bursts.
        event_filter=EventFilter(event_types={"item_received", "storage_delta"}),
    ):
        writer.write(event)


if __name__ == "__main__":
    main()
