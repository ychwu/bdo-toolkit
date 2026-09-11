"""Live progress and automatic completion for passive transfer calibration.

After successful final validation, replaces discovered transfer families in
opcodes.local, preserving unrelated families and backing up an existing file.
Ctrl+C exits without writing. The user performs every in-game action.
"""

from pathlib import Path

from bdo_toolkit.calibration import CalibrationProgress, CalibrationSession, update_profile


PROFILE = Path("opcodes.local")
ITEM_ID = 15156


def show_progress(update: CalibrationProgress) -> None:
    # Replace the previous UI observation list; this is not an event queue.
    # These records guide the user, but never authorize stopping or saving.
    for observation in update.observations:
        print(
            f"Provisional {observation.direction}: "
            f"{observation.item_record_count}/{observation.record_count} watched records, "
            f"total quantity {observation.item_quantity} "
            f"(frame {observation.frame_number})",
            flush=True,
        )
    if update.kind == "finished":
        print("Calibration finished." if update.result is not None else "Calibration failed.", flush=True)
        return
    if update.kind == "finalizing":
        print("Required evidence found; checking the finalized capture...", flush=True)
        return
    opcodes = ", ".join(f"0x{opcode:04X}" for opcode in update.detected_opcodes)
    layouts = ", ".join(f"{s.event}=0x{s.opcode:04X}" for s in update.specs)
    print(f"Current candidates: {opcodes or 'none'}; layouts: {layouts or 'none'}", flush=True)
    if update.missing_events:
        print(f"Still needed: {', '.join(sorted(update.missing_events))}", flush=True)
    if update.issues:
        print("Evidence: " + "; ".join(update.issues), flush=True)


def main() -> None:
    try:
        with CalibrationSession(
            item_id=ITEM_ID, quantity=1,
            stop_on_complete=True, on_update=show_progress,
        ) as session:
            print("Listening. Use five matching unstackables in Velia or Heidel.", flush=True)
            print("Deposit 1, deposit the remaining 4, then withdraw all 5.", flush=True)
            print("Capture finishes automatically; Ctrl+C aborts without writing.", flush=True)
            result = session.wait()
            assert result is not None
    except KeyboardInterrupt:
        print("Calibration cancelled; no profile written.")
        return
    print(result.summary())
    print(update_profile(result, PROFILE).summary())


if __name__ == "__main__":
    main()
