"""Command-line interface: ``bdo-toolkit <command>``."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .capture import capture_live, replay_pcap
from ._protocol import DEFAULT_SERVER_PORTS
from .calibration import (
    CALIBRATION_ACTIONS,
    CalibrationResult,
    DirectionMismatchError,
    calibrate_live,
    calibrate_pcap,
    reset_profile,
    update_profile,
)
from .origin_learning import (
    CompanionObservation,
    OriginLearner,
    promote_origin_candidates,
)
from .writers import ConsoleEventWriter, JsonlEventWriter


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer: {value!r}") from exc
    if not 1 <= number <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("value must be between 1 and 4294967295")
    return number


def _nonnegative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a number: {value!r}") from exc
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("value must be finite and non-negative")
    return number


def _probability(value: str) -> float:
    number = _nonnegative_float(value)
    if number > 1:
        raise argparse.ArgumentTypeError("value must be between 0 and 1")
    return number


def _parse_ports(value: str) -> tuple[int, ...]:
    ports: list[int] = []
    for piece in value.split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            port = int(piece)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid port: {piece!r}") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port out of range: {port}")
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("at least one port is required")
    return tuple(dict.fromkeys(ports))


def _add_decode_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        help="path to a local opcodes.json (default: bundled profile)",
    )
    parser.add_argument(
        "--ports",
        type=_parse_ports,
        default=DEFAULT_SERVER_PORTS,
        metavar="PORTS",
        help="comma-separated BDO server source ports (default: 8884,8885,8889)",
    )
    parser.add_argument(
        "--event-type",
        action="append",
        dest="event_types",
        metavar="TYPE",
        help="only yield this event type (repeatable), e.g. storage_delta",
    )
    parser.add_argument(
        "--source",
        action="append",
        dest="sources",
        metavar="SOURCE",
        help='only yield this source (repeatable), e.g. "Batch Storage Deposit"',
    )
    parser.add_argument(
        "--item-id",
        action="append",
        dest="item_ids",
        type=_positive_int,
        metavar="ITEM_ID",
        help="only yield this item id (repeatable)",
    )
    parser.add_argument(
        "--include-legacy-opcodes",
        action="store_true",
        help="also decode legacy observed opcodes from older captures",
    )
    parser.add_argument(
        "--ignore-profile",
        action="store_true",
        help="ignore the opcode profile and use built-in current opcodes",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="emit newline-delimited JSON instead of human-readable lines",
    )
    parser.add_argument(
        "--deposit-origin",
        choices=("worker", "manual", "unknown"),
        default=None,
        help=(
            "only yield storage_delta events with this classified deposit "
            "origin (worker deposits vs manual deposits)"
        ),
    )


def _writer(args: argparse.Namespace):
    return JsonlEventWriter() if args.jsonl else ConsoleEventWriter()


def _run_replay(args: argparse.Namespace) -> int:
    writer = _writer(args)
    count = 0
    for event in replay_pcap(
        args.pcap,
        opcode_profile=args.profile,
        ports=args.ports,
        include_legacy_opcodes=args.include_legacy_opcodes,
        ignore_opcode_profile=args.ignore_profile,
        event_types=set(args.event_types) if args.event_types else None,
        sources=set(args.sources) if args.sources else None,
        item_ids=set(args.item_ids) if args.item_ids else None,
        deposit_origins={args.deposit_origin} if args.deposit_origin else None,
    ):
        writer.write(event)
        count += 1
    print(f"decoded {count} events", file=sys.stderr)
    return 0


def _run_live(args: argparse.Namespace) -> int:
    writer = _writer(args)
    try:
        for event in capture_live(
            opcode_profile=args.profile,
            interface=args.iface,
            ports=args.ports,
            include_legacy_opcodes=args.include_legacy_opcodes,
            ignore_opcode_profile=args.ignore_profile,
            event_types=set(args.event_types) if args.event_types else None,
            sources=set(args.sources) if args.sources else None,
            item_ids=set(args.item_ids) if args.item_ids else None,
            deposit_origins={args.deposit_origin} if args.deposit_origin else None,
            capture_seconds=args.capture_seconds,
            event_queue_size=args.event_queue_size,
        ):
            writer.write(event)
    except KeyboardInterrupt:
        pass
    return 0


def _print_calibration_result(result: CalibrationResult, verbose: bool) -> None:
    print(f"scanned {result.frames_scanned} frames", file=sys.stderr)
    if not result.specs:
        print("no message specs promoted", file=sys.stderr)
    for spec in result.specs:
        fields = [spec.event, f"opcode=0x{spec.opcode:04X}", f"length={spec.length}"]
        for name in (
            "item_id_offset",
            "quantity_offset",
            "item_instance_offset",
            "context_offset",
            "inventory_slot_offset",
            "repeat_stride",
            "source_instance_offset",
            "quantity_removed_offset",
            "quantity_added_offset",
            "destination_instance_offset",
        ):
            value = getattr(spec, name)
            if value is not None:
                fields.append(f"{name}={value}")
        if spec.score is not None:
            fields.append(f"confidence={spec.score:.2f}")
        print("discovered " + " ".join(fields))
    _FAMILY_LABEL = {"into_inventory": "storage->inventory", "into_storage": "inventory->storage"}
    detected = {
        _FAMILY_LABEL[e.detected_family]
        for e in result.evidence
        if e.detected_family is not None
    }
    if detected:
        print(f"detected direction(s): {', '.join(sorted(detected))}", file=sys.stderr)
    if verbose:
        for line in result.ignored:
            print(line, file=sys.stderr)
        for e in result.evidence:
            print(
                f"classify opcode=0x{e.opcode:04X} family={e.detected_family} "
                f"reference_frame={e.reference_frame} context_label={e.context_label} "
                f"storage_context={e.storage_context}",
                file=sys.stderr,
            )


def _run_calibrate(args: argparse.Namespace) -> int:
    if args.pcap is not None and args.capture_seconds is not None:
        print(
            "error: --capture-seconds applies to live calibration only; "
            "omit it when using --pcap",
            file=sys.stderr,
        )
        return 2

    if args.action == "auto":
        instruction = (
            f"move item {args.item_id} from storage to inventory and back "
            "(either order)"
        )
    else:
        instruction = f"perform the {args.action} action with item {args.item_id} once"

    try:
        if args.pcap is not None:
            result = calibrate_pcap(
                args.pcap,
                item_id=args.item_id,
                quantity=args.qty,
                action=args.action,
                ports=args.ports,
                min_confidence=args.min_confidence,
            )
        else:
            if args.capture_seconds is not None:
                stop_instruction = f"stopping automatically after {args.capture_seconds:g}s"
            else:
                stop_instruction = "press Ctrl+C when done"
            print(f"listening -- {instruction}, {stop_instruction}", file=sys.stderr)
            result = calibrate_live(
                item_id=args.item_id,
                quantity=args.qty,
                action=args.action,
                ports=args.ports,
                interface=args.iface,
                capture_seconds=args.capture_seconds,
                min_confidence=args.min_confidence,
            )
    except DirectionMismatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_calibration_result(result, args.verbose)

    if not args.write:
        if result.specs:
            print(
                "dry run: pass --write PATH to merge these specs into a profile",
                file=sys.stderr,
            )
        return 0 if result.specs else 1

    if not result.specs:
        print("nothing to write", file=sys.stderr)
        return 1

    update = update_profile(
        result,
        args.write,
        action=args.action,
        replace=args.replace,
    )
    print(update.summary(), file=sys.stderr)
    return 0


def _run_reset_profile(args: argparse.Namespace) -> int:
    backup = reset_profile(args.path, args.calibration_item_id)
    print(f"reset {args.path}", file=sys.stderr)
    if backup is not None:
        print(f"backup at {backup}", file=sys.stderr)
    return 0


def _run_origin_learn(args: argparse.Namespace) -> int:
    learner = OriginLearner.load(
        args.candidates,
        min_observations=args.min_observations,
    )

    def observe(observation: CompanionObservation) -> None:
        candidate = learner.observe(observation)
        status = (
            "confirmed"
            if candidate.confirmed(learner.min_observations)
            else "candidate"
        )
        pair = " -> ".join(
            f"0x{opcode:04X}" for opcode in candidate.companion_opcodes
        )
        print(
            f"origin {status}: delta=0x{candidate.delta_opcode:04X} "
            f"companions={pair} observations={candidate.observations}",
            file=sys.stderr,
        )

    try:
        if args.pcaps:
            for pcap in args.pcaps:
                for _ in replay_pcap(
                    pcap,
                    opcode_profile=args.profile,
                    ports=args.ports,
                    origin_observer=observe,
                ):
                    pass
        else:
            print(
                "listening for structurally correlated worker deposits; "
                "press Ctrl+C when done",
                file=sys.stderr,
            )
            for _ in capture_live(
                opcode_profile=args.profile,
                interface=args.iface,
                ports=args.ports,
                capture_seconds=args.capture_seconds,
                origin_observer=observe,
            ):
                pass
    except KeyboardInterrupt:
        pass
    finally:
        learner.save(args.candidates)

    print(
        f"saved {len(learner.candidates)} origin candidate family/families "
        f"to {args.candidates}",
        file=sys.stderr,
    )
    for candidate in learner.candidates:
        pair = " -> ".join(
            f"0x{opcode:04X}" for opcode in candidate.companion_opcodes
        )
        status = (
            "confirmed"
            if candidate.confirmed(learner.min_observations)
            else "candidate"
        )
        print(
            f"{status}: delta=0x{candidate.delta_opcode:04X} "
            f"companions={pair} lengths={candidate.companion_lengths} "
            f"observations={candidate.observations}",
        )
    return 0 if learner.candidates else 1


def _run_origin_promote(args: argparse.Namespace) -> int:
    result = promote_origin_candidates(
        args.candidates,
        args.profile,
        min_observations=args.min_observations,
    )
    if not result.written:
        print("no new confirmed origin companion families to promote", file=sys.stderr)
        return 1
    print(
        f"promoted {len(result.added)} origin companion family/families "
        f"into {result.path}",
        file=sys.stderr,
    )
    if result.backup_path is not None:
        print(f"backup at {result.backup_path}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bdo-toolkit",
        description=(
            "Passive, read-only BDO packet telemetry: decode pcaps or live "
            "capture into structured item events, and calibrate opcode "
            "profiles after game patches."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    replay = subparsers.add_parser(
        "replay", help="decode a .pcap/.pcapng file into events"
    )
    replay.add_argument("pcap", type=Path, help="capture file to decode")
    _add_decode_arguments(replay)
    replay.set_defaults(func=_run_replay)

    live = subparsers.add_parser(
        "live", help="passively capture live traffic and decode events"
    )
    _add_decode_arguments(live)
    live.add_argument("--iface", help="capture interface (default: auto-detect)")
    live.add_argument(
        "--capture-seconds",
        type=_nonnegative_float,
        default=None,
        metavar="SECONDS",
        help="stop automatically after this many seconds (default: Ctrl+C)",
    )
    live.set_defaults(func=_run_live)
    live.add_argument(
        "--event-queue-size",
        type=_positive_int,
        default=1024,
        metavar="COUNT",
        help="maximum decoded events buffered for the consumer (default: 1024)",
    )

    calibrate = subparsers.add_parser(
        "calibrate",
        help="discover opcode specs from a capture of a known in-game action",
    )
    calibrate.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help=(
            "calibrate offline from this capture file; omit to listen live "
            "(perform the action, then press Ctrl+C to calibrate)"
        ),
    )
    calibrate.add_argument(
        "--capture-seconds",
        type=_nonnegative_float,
        default=None,
        metavar="SECONDS",
        help="stop the live listening window automatically after this many seconds",
    )
    calibrate.add_argument(
        "--item-id",
        type=_positive_int,
        required=True,
        help="decimal item id used for the calibration action (Potato: 7003)",
    )
    calibrate.add_argument(
        "--qty", type=_positive_int, default=None, help="expected quantity for the action"
    )
    calibrate.add_argument(
        "--action",
        choices=CALIBRATION_ACTIONS + ("auto",),
        default="auto",
        help=(
            "calibration workflow (default: auto). auto detects both transfer "
            "directions from packet structure -- just move the item to storage "
            "and back. Explicit directions are strict and refuse a capture whose "
            "structure contradicts the declared action. loot-preview is a "
            "separate optional gathering calibration."
        ),
    )
    calibrate.add_argument(
        "--ports",
        type=_parse_ports,
        default=DEFAULT_SERVER_PORTS,
        metavar="PORTS",
        help="comma-separated BDO server source ports (default: 8884,8885,8889)",
    )
    calibrate.add_argument("--iface", help="capture interface for live calibration")
    calibrate.add_argument(
        "--min-confidence",
        type=_probability,
        default=0.80,
        metavar="FLOAT",
        help="minimum calibration confidence from 0 to 1 (default: 0.80)",
    )
    calibrate.add_argument(
        "--write",
        type=Path,
        default=None,
        metavar="PATH",
        help="merge discovered specs into this opcodes.json (default: dry run)",
    )
    calibrate.add_argument(
        "--replace",
        action="store_true",
        help="clear this action's existing profile entries before merging",
    )
    calibrate.add_argument(
        "--verbose",
        action="store_true",
        help="also print ignored calibration candidates and reasons",
    )
    calibrate.set_defaults(func=_run_calibrate)

    reset = subparsers.add_parser(
        "reset-profile", help="write an empty active opcode profile"
    )
    reset.add_argument("path", type=Path, help="profile file to reset")
    reset.add_argument(
        "--calibration-item-id",
        type=_positive_int,
        default=7003,
        help="item id recorded in the fresh profile (default: 7003)",
    )
    reset.set_defaults(func=_run_reset_profile)

    origin_learn = subparsers.add_parser(
        "origin-learn",
        help="observe structural worker companions and persist candidate families",
    )
    origin_learn.add_argument(
        "--pcap",
        action="append",
        dest="pcaps",
        type=Path,
        default=None,
        help="inspect this capture instead of listening live (repeatable)",
    )
    origin_learn.add_argument(
        "--profile",
        type=Path,
        required=True,
        help="active opcode profile used to decode storage-delta frames",
    )
    origin_learn.add_argument(
        "--candidates",
        type=Path,
        default=Path("opcodes.origin-candidates.json"),
        help=(
            "candidate output file "
            "(default: opcodes.origin-candidates.json)"
        ),
    )
    origin_learn.add_argument(
        "--min-observations",
        type=_positive_int,
        default=2,
        help="observations required for confirmed status (default: 2)",
    )
    origin_learn.add_argument(
        "--ports",
        type=_parse_ports,
        default=DEFAULT_SERVER_PORTS,
        metavar="PORTS",
        help="comma-separated BDO server source ports (default: 8884,8885,8889)",
    )
    origin_learn.add_argument("--iface", help="capture interface for live learning")
    origin_learn.add_argument(
        "--capture-seconds",
        type=_nonnegative_float,
        default=None,
        metavar="SECONDS",
        help="stop live learning automatically after this many seconds",
    )
    origin_learn.set_defaults(func=_run_origin_learn)

    origin_promote = subparsers.add_parser(
        "origin-promote",
        help="explicitly promote confirmed origin candidates into a profile",
    )
    origin_promote.add_argument("candidates", type=Path, help="candidate JSON file")
    origin_promote.add_argument(
        "--profile",
        type=Path,
        required=True,
        help="opcode profile to update",
    )
    origin_promote.add_argument(
        "--min-observations",
        type=_positive_int,
        default=None,
        help="override the candidate file's confirmation threshold",
    )
    origin_promote.set_defaults(func=_run_origin_promote)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
