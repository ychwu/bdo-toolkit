"""Internal entry points for fail-closed storage-origin correlation."""

from typing import Optional

from ._origin.models import (
    DecrementSpec,
    ORIGIN_MANUAL,
    ORIGIN_UNKNOWN,
    ORIGIN_WORKER,
    SOURCE_PLAYER_INVENTORY,
    SOURCE_WORKER_PRODUCTION,
)
from ._origin.tracker import DepositOriginTracker

DecrementSpec.__module__ = __name__
DepositOriginTracker.__module__ = __name__
