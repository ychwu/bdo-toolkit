"""Out-of-band protocol compatibility diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional


@dataclass(frozen=True)
class DecoderDiagnostic:
    """One deduplicated decoder-compatibility warning.

    Diagnostics are deliberately not :class:`BDOEvent` objects and therefore
    bypass event filters. A storage-ID-filtered production app can learn that
    its profile stopped resolving destinations even when no matching event can
    be delivered.
    """

    code: str
    message: str
    severity: str = "warning"
    subsystem: str = "storage"
    opcode: Optional[int] = None
    requested_storage_ids: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DecoderHealth:
    """Snapshot of storage-decoder compatibility, separate from packet loss."""

    storage_status: str = "not_observed"
    storage_messages_observed: int = 0
    storage_messages_decoded: int = 0
    storage_records_decoded: int = 0
    storage_destination_failures: int = 0
    storage_geometry_failures: int = 0
    diagnostics_emitted: int = 0

    @property
    def storage_is_compatible(self) -> Optional[bool]:
        if self.storage_status == "not_observed":
            return None
        return self.storage_status == "compatible"

    def to_dict(self) -> dict[str, object]:
        output = asdict(self)
        output["storage_is_compatible"] = self.storage_is_compatible
        return output
