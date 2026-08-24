"""Track mob-drop item receipts observed during one live run."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from bdo_toolkit import EventFilter, capture_live


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"
MOB_DROPS = EventFilter(
    event_types={"item_received"},
    sources={"Mob Drop"},
)


def main() -> None:
    if not PROFILE.is_file():
        raise FileNotFoundError(
            f"opcode profile not found: {PROFILE}; fetch or calibrate it first"
        )

    totals: Counter[int] = Counter()
    print("Collect mob drops in game. Press Ctrl+C to stop.")
    for event in capture_live(
        opcode_profile=PROFILE,
        event_filter=MOB_DROPS,
    ):
        totals[event.item_id] += event.quantity
        print(
            f"item_id={event.item_id} quantity={event.quantity} "
            f"total_this_run={totals[event.item_id]}",
            flush=True,
        )


if __name__ == "__main__":
    main()
