"""One passive grind stream: confirmed mob drops, optional Agris and solo XP."""
import argparse
import sys

from bdo_toolkit import BDOEvent, LiveCaptureOptions, load_opcode_profile
from bdo_toolkit.agris import AgrisBalance
from bdo_toolkit.grind import GrindFeatureError, GrindSession
from bdo_toolkit.xp import SOLO_WARNING, XPReading


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--xp", action="store_true", help="enable experimental solo XP using the saved layout")
    parser.add_argument("--agris", action="store_true", help="enable Agris using the saved layout")
    parser.add_argument("--agris-cap", type=int, help="your known Agris maximum; required with --agris")
    parser.add_argument("--interface")
    parser.add_argument("--local-ip")
    parser.add_argument("--seconds", type=float)
    parser.add_argument("--save-pcap", help="optional new private .pcap/.pcapng file; never overwritten")
    args = parser.parse_args()
    if args.agris != (args.agris_cap is not None):
        parser.error("provide --agris and --agris-cap together")
    profile = load_opcode_profile(args.profile)
    if args.xp:
        print(SOLO_WARNING, file=sys.stderr)
        print("First XP update is the baseline, not a measured gain.", file=sys.stderr)
    print("Stop before switching characters. Updates are not correlated to individual kills.", file=sys.stderr)
    session = GrindSession(profile=profile, track_xp=args.xp, track_agris=args.agris,
        expected_maximum_points=args.agris_cap, capture_seconds=args.seconds, save_pcap=args.save_pcap,
        live_options=LiveCaptureOptions(interface=args.interface, local_ip=args.local_ip))
    with session:
        print("CAPTURE READY. Ctrl+C stops.", file=sys.stderr)
        try:
            for event in session.events():
                if isinstance(event, BDOEvent):
                    print(f"DROP | item {event.item_id} | +{event.quantity:,}")
                elif isinstance(event, XPReading):
                    delta = "baseline" if event.delta_xp is None else f"{event.delta_xp:+,}"
                    print(f"XP | Lv {event.level} | {event.current_xp:,}/{event.required_xp:,} "
                          f"({event.percentage:.3f}%) | change {delta} | net {event.net_xp:+,}")
                elif isinstance(event, AgrisBalance):
                    print(f"AGRIS | {event.remaining_points:,}/{event.maximum_points:,}")
                elif isinstance(event, GrindFeatureError):
                    print(f"{event.feature.upper()} DISABLED | {event.reason}", file=sys.stderr)
        except KeyboardInterrupt:
            pass
    print("Final status:", session.status.to_dict(), file=sys.stderr)
    print("Capture health:", session.health.to_dict(), file=sys.stderr)


if __name__ == "__main__":
    main()
