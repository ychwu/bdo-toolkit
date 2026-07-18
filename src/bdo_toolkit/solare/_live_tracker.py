"""Structured progress tracking for opcode-agnostic Solare capture."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Optional

from bdo_toolkit._protocol import BDOFrame

from ._constants import (
    DISCOVERY_MAX_FRAME_LENGTH,
    DISCOVERY_MIN_FAMILY_FRAMES,
    DISCOVERY_MIN_FRAME_LENGTH,
    DISCOVERY_MIN_RICH_RECORDS,
)
from ._discovery import SolareDiscoveryResult, discover_solare
from .models import SolareUpdate, SolareUpdateKind


class LiveSolareDiscoveryTracker:
    """Refresh structural discovery at useful milestones and emit updates."""

    def __init__(self, emit: Callable[[SolareUpdate], None]) -> None:
        self._emit = emit
        self._all_frames: list[BDOFrame] = []
        self._frames: list[BDOFrame] = []
        self._family_counts: Counter[tuple[object, int, int]] = Counter()
        self._announced_menu = False
        self._announced_ranked_players = 300
        self._announced_rich: Optional[tuple[object, ...]] = None
        self._announced_cross_check = 0
        self._announced_confirmed = False
        self._confirmed_frames: Optional[tuple[BDOFrame, ...]] = None
        self._dirty = False
        self.result = SolareDiscoveryResult(0, ())

    def observe(self, frame: BDOFrame) -> None:
        if self._confirmed_frames is not None:
            return
        if not (
            frame.flag == 0
            and DISCOVERY_MIN_FRAME_LENGTH
            <= frame.length
            <= DISCOVERY_MAX_FRAME_LENGTH
        ):
            return

        self._all_frames.append(frame)
        self._frames.append(frame)
        self._dirty = True
        family_key = (frame.context.flow, frame.opcode, frame.length)
        self._family_counts[family_key] += 1
        family_count = self._family_counts[family_key]

        ranked_known = self.result.ranked_candidate is not None
        rich_interval = family_count in {
            DISCOVERY_MIN_RICH_RECORDS // 2,
            250,
            300,
            310,
        }
        related_interval = (
            ranked_known
            and family_count >= DISCOVERY_MIN_FAMILY_FRAMES
            and family_count in {10, 50}
        )
        if family_count == 24 or rich_interval or related_interval:
            self.refresh()

    @property
    def complete(self) -> bool:
        return self._confirmed_frames is not None

    @property
    def confirmed_frames(self) -> Optional[tuple[BDOFrame, ...]]:
        """Exact first structurally confirmed window, latched permanently."""

        return self._confirmed_frames

    def refresh(self) -> SolareDiscoveryResult:
        if self._confirmed_frames is not None:
            return self.result
        if not self._dirty:
            return self.result
        self.result = discover_solare(self._frames)
        self._dirty = False
        if self.result.confirmed:
            self._confirmed_frames = tuple(self._all_frames)
        self._announce_progress()
        return self.result

    def _announce_progress(self) -> None:
        result = self.result
        menu = result.menu_context
        if menu is not None and not self._announced_menu:
            self._announced_menu = True
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.MENU_CONTEXT,
                    message=(
                        "Solare menu/history-like traffic was observed; open or "
                        "refresh the Leaderboard tab"
                    ),
                )
            )

        ranked = result.ranked_candidate
        if (
            not result.confirmed
            and result.partial_overall is None
            and ranked is not None
            and ranked.record_count >= self._announced_ranked_players + 100
        ):
            self._announced_ranked_players = (
                ranked.record_count // 100
            ) * 100
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.RANKED_PROGRESS,
                    message=(
                        f"{ranked.record_count} unique ranked players recovered; "
                        "waiting for class balance and the top-100 cross-check"
                    ),
                    ranked_players=ranked.record_count,
                )
            )

        rich = result.rich
        if rich is not None:
            identity = (
                rich.flow,
                rich.frame_length,
                rich.record_stride,
                rich.name_offset,
                rich.rank_offset,
                rich.class_offset,
            )
            if identity != self._announced_rich:
                self._announced_rich = identity
                self._emit(
                    SolareUpdate(
                        kind=SolareUpdateKind.RICH_CANDIDATE,
                        message=(
                            f"structurally valid rich table: {rich.record_count} "
                            f"players across {len(rich.class_counts)} class groups"
                        ),
                        ranked_players=rich.record_count,
                    )
                )

        partial = result.partial_overall
        if (
            not result.confirmed
            and ranked is not None
            and partial is not None
            and self._announced_cross_check == 0
        ):
            self._announced_cross_check = partial.record_count
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.CROSS_CHECK,
                    message=(
                        f"{partial.record_count}/{partial.record_count} recovered "
                        "overall rank/name pairs match; continuing for 100"
                    ),
                    ranked_players=ranked.record_count,
                    overall_players=partial.record_count,
                    exact_cross_check=partial.record_count,
                )
            )

        if result.confirmed and not self._announced_confirmed:
            self._announced_confirmed = True
            assert result.rich is not None
            assert result.overall is not None
            self._emit(
                SolareUpdate(
                    kind=SolareUpdateKind.SNAPSHOT_CONFIRMED,
                    message=(
                        "opcode-agnostic Arena of Solare leaderboard confirmed"
                    ),
                    ranked_players=result.rich.record_count,
                    overall_players=result.overall.record_count,
                    exact_cross_check=result.overall.record_count,
                )
            )
