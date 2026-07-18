"""Tiny example: print worker-attributed storage deposits.

Usage: python examples/storage_batch_log.py path/to/session.pcapng

Every storage_delta event carries event.deposit_origin:
"worker" / "manual" / "unknown", classified from packet structure (a manual
deposit is preceded by a matching source-stack decrement; a worker deposit is
correlated with an ordered companion pair inside a bounded eight-message
lookahead, using a high-entropy token from before the delta's first item
record). Unrelated messages may appear inside that window. "unknown" means the
evidence was absent, ambiguous, or insufficient -- the toolkit refuses to
guess. Character-load storage contents observed during initial login and
character switching are separate ``storage_snapshot`` events and are excluded
by this example's ``storage_delta`` filter.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bdo_toolkit import EventFilter, JsonlEventWriter, replay_pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="capture file to decode")
    args = parser.parse_args()
    writer = JsonlEventWriter()
    for event in replay_pcap(
        args.pcap,
        event_filter=EventFilter(
            event_types={"storage_delta"},
            deposit_origins={"worker"},
        ),
    ):
        writer.write(event)


if __name__ == "__main__":
    main()
