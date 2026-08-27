"""Command-line interface: ``bdo-toolkit <command>``."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from ._capture_options import LiveCaptureOptions, PacketCaptureOptions
from .capture import capture_live, replay_pcap
from .diagnostics import DecoderDiagnostic
from ._protocol import DEFAULT_SERVER_PORTS
from .calibration import (
    CalibrationAuthorityError,
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
from .remote_profiles import (
    DEFAULT_REMOTE_PROFILE_MAX_BYTES,
    DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS,
    fetch_opcode_profile,
)
from .filters import EventFilter
from .writers import ConsoleEventWriter, JsonlEventWriter
from .solare import (
    SolareCaptureResult,
    SolareUpdate,
    SolareUpdateKind,
    capture_solare_snapshot,
    replay_solare,
)
from .solare._constants import SOLARE_DEFAULT_CAPTURE_SECONDS


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer: {value!r}") from exc
    if not 1 <= number <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("value must be between 1 and 4294967295")
    return number


def _storage_id(value: str) -> int:
    try:
        number = int(value, 16 if value.lower().startswith("0x") else 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"expected a decimal or 0x-prefixed integer: {value!r}"
        ) from exc
    if not 1 <= number <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("value must be between 1 and 0xFFFFFFFF")
    return number


def _nonnegative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a number: {value!r}") from exc
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("value must be finite and non-negative")
    return number


def _positive_float(value: str) -> float:
    number = _nonnegative_float(value)
    if number == 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
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
        required=True,
        help="path to the active opcode profile",
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
        help=(
            'only yield this semantic source (repeatable), e.g. "Mob Drop" '
            'or "Worker Production"'
        ),
    )
    parser.add_argument(
        "--storage-id",
        action="append",
        dest="storage_ids",
        type=_storage_id,
        metavar="ID",
        help="only yield this storage destination ID (repeatable; decimal or 0x...)",
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
        "--jsonl",
        action="store_true",
        help="emit newline-delimited JSON instead of human-readable lines",
    )


def _writer(args: argparse.Namespace):
    return JsonlEventWriter() if args.jsonl else ConsoleEventWriter()


def _decode_filter(args: argparse.Namespace) -> EventFilter | None:
    if not any(
        (
            args.event_types,
            args.sources,
            args.storage_ids,
            args.item_ids,
        )
    ):
        return None
    return EventFilter(
        event_types=args.event_types,
        sources=args.sources,
        storage_ids=args.storage_ids,
        item_ids=args.item_ids,
    )


def _report_decoder_diagnostic(diagnostic: DecoderDiagnostic) -> None:
    print(
        f"decoder {diagnostic.severity} [{diagnostic.code}]: "
        f"{diagnostic.message}",
        file=sys.stderr,
    )


def _run_replay(args: argparse.Namespace) -> int:
    writer = _writer(args)
    count = 0
    for event in replay_pcap(
        args.pcap,
        opcode_profile=args.profile,
        ports=args.ports,
        event_filter=_decode_filter(args),
        on_diagnostic=_report_decoder_diagnostic,
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
            live_options=LiveCaptureOptions(
                interface=args.iface,
                ports=args.ports,
                event_queue_size=args.event_queue_size,
            ),
            event_filter=_decode_filter(args),
            capture_seconds=args.capture_seconds,
            on_diagnostic=_report_decoder_diagnostic,
        ):
            writer.write(event)
    except KeyboardInterrupt:
        pass
    return 0


def _run_profile_fetch(args: argparse.Namespace) -> int:
    result = fetch_opcode_profile(
        args.url,
        args.output,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        backup=args.backup,
    )
    print(
        f"installed opcode profile revision {result.revision} at {result.path}",
        file=sys.stderr,
    )
    print(f"profile sha256: {result.profile_sha256}", file=sys.stderr)
    if result.backup_path is not None:
        print(f"backup at {result.backup_path}", file=sys.stderr)
    return 0


def _write_solare_result(
    result: SolareCaptureResult,
    *,
    output: Path | None,
    include_raw: bool,
) -> None:
    serialized = result.to_json(include_raw=include_raw) + "\n"
    if output is None:
        sys.stdout.write(serialized)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(serialized, encoding="utf-8")
    print(f"wrote Solare result to {output}", file=sys.stderr)


def _same_output_path(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    left = left.expanduser()
    right = right.expanduser()
    try:
        if left.exists() and right.exists() and left.samefile(right):
            return True
    except OSError:
        pass
    return left.resolve() == right.resolve()


def _run_solare_replay(args: argparse.Namespace) -> int:
    if _same_output_path(args.pcap, args.output):
        raise ValueError("--output must not overwrite the replay input capture")
    result = replay_solare(
        args.pcap,
        ports=args.ports,
        retain_raw_extensions=args.include_raw,
    )
    _write_solare_result(
        result,
        output=args.output,
        include_raw=args.include_raw,
    )
    return 0 if result.complete else 1


def _run_solare_live(args: argparse.Namespace) -> int:
    if _same_output_path(args.save_pcap, args.output):
        raise ValueError("--output and --save-pcap must use different paths")

    def report(update: SolareUpdate) -> None:
        if args.quiet or update.kind is SolareUpdateKind.FINISHED:
            return
        print(f"[{update.kind.value}] {update.message}", file=sys.stderr, flush=True)

    result = capture_solare_snapshot(
        capture_options=PacketCaptureOptions(
            interface=args.iface,
            local_ip=args.local_ip,
            ports=args.ports,
            use_bpf=not args.no_bpf,
        ),
        capture_seconds=args.capture_seconds,
        save_pcap=args.save_pcap,
        stop_on_complete=args.stop_on_complete,
        retain_raw_extensions=args.include_raw,
        on_update=report,
    )
    _write_solare_result(
        result,
        output=args.output,
        include_raw=args.include_raw,
    )
    return 0 if result.complete else 1


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
            "record_count_offset",
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
    _FAMILY_LABEL = {
        "into_inventory": "storage->inventory",
        "into_storage": "inventory->storage",
    }
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
            f"with five matching unstackable items having raw ID {args.item_id}: "
            "perform the in-game actions deposit 1, deposit 4, then withdraw "
            "all 5 while capture passively listens"
        )
    elif args.action == "inventory-to-storage":
        instruction = (
            f"deposit matching item {args.item_id} records using at least "
            "two different batch counts"
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
                stop_instruction = (
                    f"stopping automatically after {args.capture_seconds:g}s"
                )
            else:
                stop_instruction = "press Ctrl+C when done"
            print(f"listening -- {instruction}, {stop_instruction}", file=sys.stderr)
            result = calibrate_live(
                item_id=args.item_id,
                quantity=args.qty,
                action=args.action,
                capture_options=PacketCaptureOptions(
                    interface=args.iface,
                    ports=args.ports,
                ),
                capture_seconds=args.capture_seconds,
                min_confidence=args.min_confidence,
            )
    except (DirectionMismatchError, CalibrationAuthorityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_calibration_result(result, args.verbose)

    if not args.write:
        if result.specs:
            write_description = (
                "merge these specs into a profile"
                if args.merge
                else "write these specs and replace stale applicable profile entries"
            )
            print(
                f"dry run: pass --write PATH to {write_description}",
                file=sys.stderr,
            )
        return 0 if result.specs else 1

    if not result.specs:
        print("nothing to write", file=sys.stderr)
        return 1

    try:
        update = update_profile(
            result,
            args.write,
            action=args.action,
            replace=not args.merge,
        )
    except CalibrationAuthorityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
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
        pair = " -> ".join(f"0x{opcode:04X}" for opcode in candidate.companion_opcodes)
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
                live_options=LiveCaptureOptions(
                    interface=args.iface,
                    ports=args.ports,
                ),
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
    print(learner.summary())
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

    profile = subparsers.add_parser(
        "profile",
        help="retrieve and manage explicit opcode profiles",
    )
    profile_subparsers = profile.add_subparsers(
        dest="profile_command",
        required=True,
    )
    profile_fetch = profile_subparsers.add_parser(
        "fetch",
        help="fetch, verify, and atomically install a remote opcode profile",
        description=(
            "Fetch, verify, and atomically install a remote opcode profile. "
            "Use only one writer per output path; cross-process locking is "
            "the caller's responsibility."
        ),
    )
    profile_fetch.add_argument("url", help="HTTPS URL of a profile envelope")
    profile_fetch.add_argument(
        "--output",
        type=Path,
        required=True,
        metavar="PATH",
        help="local profile path to create or replace",
    )
    profile_fetch.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            "network timeout in seconds "
            f"(default: {DEFAULT_REMOTE_PROFILE_TIMEOUT_SECONDS:g})"
        ),
    )
    profile_fetch.add_argument(
        "--max-bytes",
        type=_positive_int,
        default=DEFAULT_REMOTE_PROFILE_MAX_BYTES,
        metavar="BYTES",
        help=(
            "maximum accepted response size "
            f"(default: {DEFAULT_REMOTE_PROFILE_MAX_BYTES})"
        ),
    )
    profile_fetch.add_argument(
        "--no-backup",
        dest="backup",
        action="store_false",
        help="replace an existing output without preserving a backup",
    )
    profile_fetch.set_defaults(func=_run_profile_fetch, backup=True)

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

    solare = subparsers.add_parser(
        "solare",
        help="capture or replay an experimental Arena of Solare snapshot",
        description="Experimental Arena of Solare leaderboard capture and replay.",
    )
    solare_subparsers = solare.add_subparsers(
        dest="solare_command",
        required=True,
    )

    solare_replay = solare_subparsers.add_parser(
        "replay",
        help="discover a Solare leaderboard in a .pcap/.pcapng file",
        description="Replay a capture with the Experimental Arena of Solare API.",
    )
    solare_replay.add_argument("pcap", type=Path, help="capture file to inspect")
    solare_replay.add_argument(
        "--ports",
        type=_parse_ports,
        default=DEFAULT_SERVER_PORTS,
        metavar="PORTS",
        help="comma-separated BDO server source ports (default: 8884,8885,8889)",
    )
    solare_replay.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="write the result JSON here instead of stdout",
    )
    solare_replay.add_argument(
        "--include-raw",
        action="store_true",
        help=(
            "retain and include large raw gear and skill-addon buffers as hex"
        ),
    )
    solare_replay.set_defaults(func=_run_solare_replay)

    solare_live = solare_subparsers.add_parser(
        "live",
        help="listen until a complete Solare snapshot is confirmed",
        description="Capture one result with the Experimental Arena of Solare API.",
    )
    solare_live.add_argument(
        "--ports",
        type=_parse_ports,
        default=DEFAULT_SERVER_PORTS,
        metavar="PORTS",
        help="comma-separated BDO server source ports (default: 8884,8885,8889)",
    )
    solare_live.add_argument(
        "--iface",
        help="capture interface (default: auto-detect)",
    )
    solare_live.add_argument(
        "--local-ip",
        default=None,
        help="local destination IPv4 address (default: auto-detect)",
    )
    solare_live.add_argument(
        "--no-bpf",
        action="store_true",
        help="use a Python packet filter instead of BPF",
    )
    solare_duration = solare_live.add_mutually_exclusive_group()
    solare_duration.add_argument(
        "--capture-seconds",
        type=_nonnegative_float,
        default=SOLARE_DEFAULT_CAPTURE_SECONDS,
        metavar="SECONDS",
        help=(
            "stop after this many seconds "
            f"(default: {SOLARE_DEFAULT_CAPTURE_SECONDS:g})"
        ),
    )
    solare_duration.add_argument(
        "--wait-forever",
        action="store_const",
        const=None,
        dest="capture_seconds",
        help="disable the default deadline and wait for Ctrl+C or completion",
    )
    solare_live.add_argument(
        "--save-pcap",
        type=Path,
        default=None,
        metavar="PATH",
        help="record matching packets to a new .pcap or .pcapng file",
    )
    solare_live.add_argument(
        "--keep-listening",
        action="store_false",
        dest="stop_on_complete",
        help="continue after confirmation instead of stopping automatically",
    )
    solare_live.add_argument(
        "--quiet",
        action="store_true",
        help="suppress progress messages on stderr",
    )
    solare_live.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="write the result JSON here instead of stdout",
    )
    solare_live.add_argument(
        "--include-raw",
        action="store_true",
        help=(
            "retain and include large raw gear and skill-addon buffers as hex"
        ),
    )
    solare_live.set_defaults(func=_run_solare_live, stop_on_complete=True)

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
        help="decimal item id used for calibration (use matching unstackables)",
    )
    calibrate.add_argument(
        "--qty",
        type=_positive_int,
        default=None,
        help=(
            "expected per-record quantity (normally 1 for unstackables); "
            "omit for a loot-preview item whose displayed quantity is random"
        ),
    )
    calibrate.add_argument(
        "--action",
        choices=CALIBRATION_ACTIONS + ("auto",),
        default="auto",
        help=(
            "calibration workflow (default: auto). auto detects both transfer "
            "directions from packet structure. With five matching unstackables "
            "and --qty 1, the user deposits 1, deposits 4, then withdraws all 5 "
            "while capture listens; --qty remains the value in each record, not "
            "the batch size. "
            "Explicit directions are strict and refuse a capture whose structure "
            "contradicts the declared action. loot-preview is a separate optional "
            "gathering calibration; watch a known item id and omit --qty when its "
            "preview quantity is random."
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
        help=(
            "write discovered specs to this local profile path, replacing the "
            "applicable existing entries (default: dry run)"
        ),
    )
    write_mode = calibrate.add_mutually_exclusive_group()
    write_mode.add_argument(
        "--merge",
        action="store_true",
        help=(
            "advanced: preserve and deduplicate existing entries instead of "
            "replacing the applicable profile-family scope"
        ),
    )
    write_mode.add_argument(
        "--replace",
        dest="merge",
        action="store_false",
        help=argparse.SUPPRESS,
    )
    calibrate.add_argument(
        "--verbose",
        action="store_true",
        help="also print ignored calibration candidates and reasons",
    )
    calibrate.set_defaults(func=_run_calibrate, merge=False)

    reset = subparsers.add_parser(
        "reset-profile", help="write an empty active opcode profile"
    )
    reset.add_argument("path", type=Path, help="profile file to reset")
    reset.add_argument(
        "--calibration-item-id",
        type=_positive_int,
        default=15156,
        help="item id recorded in the fresh profile (default: 15156)",
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
        help=("candidate output file " "(default: opcodes.origin-candidates.json)"),
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
