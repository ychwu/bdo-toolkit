#!/usr/bin/env python3
"""Capture or replay character-load hydration and print a state summary."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from bdo_toolkit import PacketCaptureOptions
from bdo_toolkit.item_state import (
    CharacterLoadSession,
    analyze_item_state_pcap,
    format_item_state,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILE = REPOSITORY_ROOT / "opcodes.local"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Passively inspect inventory and storage hydration during initial "
            "login or a character switch."
        )
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=DEFAULT_PROFILE,
        help="active opcode profile (default: repository opcodes.local)",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        help="replay a pcap/pcapng instead of capturing live",
    )
    parser.add_argument(
        "--save-pcap",
        type=Path,
        help=(
            "save every packet admitted by the live capture filter to a raw "
            ".pcap or .pcapng file (existing files are never overwritten)"
        ),
    )
    parser.add_argument(
        "--seconds",
        type=float,
        help="stop live capture automatically after this many seconds",
    )
    parser.add_argument(
        "--interface",
        help="capture interface passed to Scapy (default: auto-detect)",
    )
    parser.add_argument(
        "--local-ip",
        help="local destination IPv4 address used by the capture filter",
    )
    parser.add_argument(
        "--ports",
        type=int,
        nargs="+",
        default=(8884, 8885, 8889),
        metavar="PORT",
        help="BDO server source ports",
    )
    parser.add_argument(
        "--no-bpf",
        action="store_true",
        help="disable the kernel BPF filter and filter packets in Python",
    )
    parser.add_argument(
        "--show-items",
        action="store_true",
        help="print every decoded item record below each summary",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the query model as JSON instead of the human report",
    )
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.seconds is not None and args.seconds < 0:
        parser.error("--seconds must be non-negative")
    if args.pcap is not None and args.seconds is not None:
        parser.error("--seconds only applies to live capture")
    if args.pcap is not None and args.save_pcap is not None:
        parser.error("--save-pcap only applies to live capture; --pcap is replay-only")
    if args.save_pcap is not None and args.save_pcap.suffix.casefold() not in {
        ".pcap",
        ".pcapng",
    }:
        parser.error("--save-pcap must end in .pcap or .pcapng")


def _print_report(args: argparse.Namespace, snapshot) -> None:
    if args.json:
        print(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_item_state(snapshot, show_items=args.show_items))


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    _validate_args(parser, args)

    if not args.profile.is_file():
        raise FileNotFoundError(f"active opcode profile not found: {args.profile}")

    if args.pcap is not None:
        snapshot = analyze_item_state_pcap(
            args.pcap,
            opcode_profile=args.profile,
            ports=tuple(args.ports),
        )
        _print_report(args, snapshot)
        return

    options = PacketCaptureOptions(
        interface=args.interface,
        local_ip=args.local_ip,
        ports=tuple(args.ports),
        use_bpf=not args.no_bpf,
    )
    session = CharacterLoadSession(
        opcode_profile=args.profile,
        capture_options=options,
        save_pcap=args.save_pcap,
    )
    print(f"Using opcode profile: {args.profile}")
    if args.save_pcap is not None:
        print(f"Saving filtered raw packets to: {args.save_pcap}")
        print(
            "PRIVACY: Raw BDO packets may expose IP, session, account, and "
            "inventory data. Do not publish this capture blindly."
        )
    print("Starting passive character-load diagnostic...")
    session.start()
    try:
        if args.seconds is None:
            input(
                "Switch characters (or finish initial login), wait until loading "
                "completes, then press Enter to summarize.\n"
            )
        else:
            print(
                f"Capture will stop in {args.seconds:g} seconds. "
                "Perform the character load now."
            )
            deadline = time.monotonic() + args.seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.2, remaining))
    except KeyboardInterrupt:
        print("\nStopping capture and summarizing collected state...")
    finally:
        snapshot = session.stop()

    _print_report(args, snapshot)


if __name__ == "__main__":
    main()
