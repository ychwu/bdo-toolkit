"""Print confirmed worker production added to town storage."""

from __future__ import annotations

import sys
from pathlib import Path

from bdo_toolkit import DecoderDiagnostic, EventFilter, capture_live


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"
WORKER_PRODUCTIONS = EventFilter(
    event_types={"storage_delta"},
    sources={"Worker Production"},
)


def report_decoder_problem(diagnostic: DecoderDiagnostic) -> None:
    print(
        f"DECODER {diagnostic.severity.upper()} [{diagnostic.code}] "
        f"{diagnostic.message}",
        file=sys.stderr,
        flush=True,
    )


def main() -> None:
    if not PROFILE.is_file():
        raise FileNotFoundError(
            f"opcode profile not found: {PROFILE}; fetch or calibrate it first"
        )

    print(
        "Waiting for worker production to reach town storage. "
        "Press Ctrl+C to stop."
    )
    for event in capture_live(
        opcode_profile=PROFILE,
        event_filter=WORKER_PRODUCTIONS,
        on_diagnostic=report_decoder_problem,
    ):
        destination = (
            event.storage_name
            or (
                f"0x{event.storage_id:08x}"
                if event.storage_id is not None
                else "unknown"
            )
        )
        storage_id = (
            f"0x{event.storage_id:08x}"
            if event.storage_id is not None
            else "unavailable"
        )
        print(
            f"source={event.source!r} destination={destination!r} "
            f"storage_id={storage_id} "
            f"item_id={event.item_id} "
            f"quantity={event.quantity}",
            flush=True,
        )


if __name__ == "__main__":
    main()
