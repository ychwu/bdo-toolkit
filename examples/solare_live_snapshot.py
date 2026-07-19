"""Capture one Arena of Solare leaderboard and print useful player fields."""

from __future__ import annotations

from bdo_toolkit.solare import (
    SolareUpdate,
    SolareUpdateKind,
    capture_solare_snapshot,
)


def show_progress(update: SolareUpdate) -> None:
    # Callbacks are synchronous: display or enqueue work, but never wait/stop
    # here. Use session.request_stop() in a session-based callback when needed.
    if update.kind is not SolareUpdateKind.FINISHED:
        print(f"[{update.kind.value}] {update.message}")


# The convenience API has a 120-second default deadline and normally stops as
# soon as one complete snapshot is confirmed. Pass capture_seconds=None only
# when an intentionally unbounded wait is appropriate.
result = capture_solare_snapshot(capture_seconds=120, on_update=show_progress)
if not result.complete or result.snapshot is None:
    raise SystemExit(f"No complete snapshot: {result.status.value} ({result.message})")

snapshot = result.snapshot
print(
    f"\n{len(snapshot.players)} players; capabilities={sorted(snapshot.capabilities)}"
)
for entry in snapshot.overall_top_100[:10]:
    player = snapshot.get_player(entry.name)
    if player is None:
        print(f"{entry.global_rank:3}. {entry.name:<24} overall only")
        continue
    performance = player.classes_played[0] if player.classes_played else None
    record = "stats unavailable"
    if performance is not None:
        record = (
            f"{performance.wins}-{performance.losses}-{performance.draws} "
            f"in {performance.matches} matches"
        )
    print(
        f"{entry.global_rank:3}. {entry.name:<24} "
        f"{player.primary_class.name or player.primary_class.code}: {record}"
    )
