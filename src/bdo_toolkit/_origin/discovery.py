"""Private deposit-origin discovery implementation."""

from __future__ import annotations

import dataclasses
from collections import OrderedDict
from typing import Optional
from ..origin_learning import CompanionObservation, discover_companion_observation
from .models import _CompanionDiscoveryKey, _PendingDeposit


class _CompanionDiscoveryCache:
    """Optional bounded byte-match cache; never owns classification decisions."""

    COMPANION_DISCOVERY_CACHE_LIMIT = 4096
    COMPANION_DISCOVERY_CACHE_BYTES = 2 * 1024 * 1024

    def __init__(self) -> None:
        self._companion_discoveries: OrderedDict[
            _CompanionDiscoveryKey, tuple[Optional[CompanionObservation], int]
        ] = OrderedDict()
        self._companion_discovery_bytes = 0

    def discover(
        self,
        pending: _PendingDeposit,
        delta_message: bytes,
        first_message: bytes,
        second_message: bytes,
        delta_prefix_end: int,
    ) -> Optional[CompanionObservation]:
        """Reuse byte-level matches, never mutable ownership or confirmation."""
        key = (
            delta_message[:delta_prefix_end], len(delta_message),
            delta_prefix_end, first_message, second_message,
        )
        cached = self._companion_discoveries.get(key)
        if cached is not None:
            self._companion_discoveries.move_to_end(key)
            observation, _size = cached
            if observation is None:
                return None
            # Identical bytes can belong to independent operations or flows.
            # Keep their observation identities and confirmation counts distinct.
            return dataclasses.replace(
                observation, timestamp=pending.timestamp, flow=pending.flow,
                stream_sequence=pending.stream_sequence,
            )

        observation = discover_companion_observation(
            delta_message=delta_message,
            first_message=first_message,
            second_message=second_message,
            timestamp=pending.timestamp,
            flow=pending.flow,
            stream_sequence=pending.stream_sequence,
            delta_prefix_end=delta_prefix_end,
        )
        size = len(key[0]) + len(first_message) + len(second_message)
        if (
            self.COMPANION_DISCOVERY_CACHE_LIMIT > 0
            and size <= self.COMPANION_DISCOVERY_CACHE_BYTES
        ):
            while self._companion_discoveries and (
                len(self._companion_discoveries)
                >= self.COMPANION_DISCOVERY_CACHE_LIMIT
                or self._companion_discovery_bytes + size
                > self.COMPANION_DISCOVERY_CACHE_BYTES
            ):
                _, (_, expired_size) = self._companion_discoveries.popitem(last=False)
                self._companion_discovery_bytes -= expired_size
            self._companion_discoveries[key] = (observation, size)
            self._companion_discovery_bytes += size
        return observation

    def clear(self) -> None:
        self._companion_discoveries.clear()
        self._companion_discovery_bytes = 0
