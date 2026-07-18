"""Capture one Arena of Solare leaderboard and print useful player fields."""

from __future__ import annotations

from bdo_toolkit.solare import SolareUpdate, capture_solare_snapshot


def show_progress(update: SolareUpdate) -> None:
    if update.kind.value != "finished":
        print(f"[{update.kind.value}] {update.message}")


result = capture_solare_snapshot(on_update=show_progress)
if not result.complete or result.snapshot is None:
    raise SystemExit(f"No complete snapshot: {result.status.value} ({result.message})")

snapshot = result.snapshot
print(f"\n{len(snapshot.players)} players; capabilities={sorted(snapshot.capabilities)}")
for player in snapshot.top_100[:10]:
    performance = player.classes_played[0] if player.classes_played else None
    record = "stats unavailable"
    if performance is not None:
        record = (
            f"{performance.wins}-{performance.losses}-{performance.draws} "
            f"in {performance.matches} matches"
        )
    print(
        f"{player.global_rank:3}. {player.name:<24} "
        f"{player.primary_class.name or player.primary_class.code}: {record}"
    )

