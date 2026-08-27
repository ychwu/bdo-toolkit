"""Live listener: print confirmed item receipts and storage additions.

The event filter intentionally excludes character-load hydration, neutral
records, and optional loot previews.
"""

from __future__ import annotations

import sys
from pathlib import Path

from bdo_toolkit import BDOEvent, DecoderDiagnostic, EventFilter, capture_live


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"
CONFIRMED_ACTIVITY = EventFilter(
    event_types={"item_received", "storage_delta"},
)


def report_decoder_problem(diagnostic: DecoderDiagnostic) -> None:
    print(
        f"DECODER {diagnostic.severity.upper()} [{diagnostic.code}] "
        f"{diagnostic.message}",
        file=sys.stderr,
        flush=True,
    )


def print_event(event: BDOEvent) -> None:
    fields = [f"[{event.timestamp_text}]", event.event_type.upper()]
    if event.source is not None:
        fields.append(f"source={event.source!r}")
    if event.storage_id is not None:
        destination = event.storage_name or f"0x{event.storage_id:08x}"
        fields.append(f"destination={destination!r}")
        fields.append(f"storage_id=0x{event.storage_id:08x}")
    fields.extend((f"item_id={event.item_id}", f"quantity={event.quantity}"))
    print(" ".join(fields), flush=True)


def main() -> None:
    if not PROFILE.is_file():
        raise FileNotFoundError(
            f"opcode profile not found: {PROFILE}; fetch or calibrate it first"
        )

    print(f"Using opcode profile: {PROFILE}", flush=True)
    print("Listening for confirmed item activity. Press Ctrl+C to stop.")
    for event in capture_live(
        opcode_profile=PROFILE,
        event_filter=CONFIRMED_ACTIVITY,
        on_diagnostic=report_decoder_problem,
    ):
        print_event(event)


if __name__ == "__main__":
    main()
