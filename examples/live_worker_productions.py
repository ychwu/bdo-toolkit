"""Print confirmed worker production added to town storage."""

from __future__ import annotations

import sys
from pathlib import Path

from bdo_toolkit import DecoderDiagnostic, EventFilter, capture_live


PROFILE = Path(__file__).resolve().parents[1] / "opcodes.local"
WORKER_PRODUCTIONS = EventFilter(
    event_types={"storage_delta"},
    deposit_origins={"worker"},
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
        print(
            f"source={event.source!r} item_id={event.item_id} "
            f"quantity={event.quantity} "
            f"deposit_origin={event.deposit_origin}",
            flush=True,
        )


if __name__ == "__main__":
    main()
