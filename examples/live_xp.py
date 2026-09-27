"""Fetch once on request, then observe experimental solo XP through the API."""
import argparse
from pathlib import Path

from bdo_toolkit import LiveCaptureOptions, fetch_opcode_profile, load_opcode_profile
from bdo_toolkit.xp import LiveXPSession, SOLO_WARNING


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--fetch-url", help="optional explicit HTTPS profile-envelope URL; installs into --profile")
    parser.add_argument("--interface")
    parser.add_argument("--local-ip")
    parser.add_argument("--seconds", type=float)
    args = parser.parse_args()
    # Fetch is an explicit app/user action, never a side effect of recording.
    profile = (fetch_opcode_profile(args.fetch_url, args.profile).profile if args.fetch_url
               else load_opcode_profile(args.profile))
    print(SOLO_WARNING)
    print("Restart before changing characters. First XP update establishes the baseline.")
    session = LiveXPSession(profile=profile, capture_seconds=args.seconds,
                            live_options=LiveCaptureOptions(interface=args.interface, local_ip=args.local_ip))
    with session:
        print("CAPTURE READY. Waiting for XP activity. Ctrl+C stops.")
        try:
            for reading in session.events():
                delta = "baseline" if reading.delta_xp is None else f"{reading.delta_xp:+,}"
                print(f"Lv {reading.level} | {reading.current_xp:,}/{reading.required_xp:,} "
                      f"({reading.percentage:.3f}%) | change {delta} | net {reading.net_xp:+,}")
        except KeyboardInterrupt:
            pass
    # Reading status after successful stop includes final drained packets.
    print("Final status:", session.status.to_dict())
    print("Capture health:", session.health.to_dict())


if __name__ == "__main__":
    main()
