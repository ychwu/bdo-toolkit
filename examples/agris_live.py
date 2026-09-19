"""Observe balances: python examples/agris_live.py --cap YOUR_KNOWN_MAXIMUM."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from bdo_toolkit import LiveCaptureOptions
from bdo_toolkit.agris import LiveAgrisSession


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cap", type=int, required=True)
    parser.add_argument("--iface")
    parser.add_argument("--capture-seconds", type=float)
    parser.add_argument("--save-pcap", type=Path)
    args = parser.parse_args()
    session = LiveAgrisSession(
        expected_maximum_points=args.cap,
        live_options=LiveCaptureOptions(interface=args.iface),
        capture_seconds=args.capture_seconds,
        save_pcap=args.save_pcap,
    )
    with session:
        print("Capture ready. Waiting for repeated balance updates; Ctrl+C stops.")
        try:
            for balance in session.events():
                print(f"Remaining: {balance.remaining_points:,} / {balance.maximum_points:,}")
        except KeyboardInterrupt:
            pass
    for balance in session.events():
        print(f"Remaining: {balance.remaining_points:,} / {balance.maximum_points:,}")
    print(session.status.to_dict(), file=sys.stderr)
    print(session.health.to_dict(), file=sys.stderr)


if __name__ == "__main__":
    main()
