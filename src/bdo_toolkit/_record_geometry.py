"""Record-layout arithmetic shared by discovery, decoding, and assembly.

These helpers do not establish count authority or validate record contents.
Callers retain their own prefix, field-width, marker, and ambiguity policies.
"""

from collections.abc import Sequence


def infer_repeat_stride(
    message_length: int, single_record_length: int, record_count: int,
) -> int | None:
    """Solve length = single-record length + (count - 1) * stride."""
    if record_count < 2:
        return None
    extra_length = message_length - single_record_length
    if extra_length <= 0 or extra_length % (record_count - 1):
        return None
    return extra_length // (record_count - 1)


def uniform_stride(offsets: Sequence[int]) -> int | None:
    """Return uniform spacing; the caller decides whether it fits a record."""
    if len(offsets) < 2:
        return None
    stride = offsets[1] - offsets[0]
    return stride if all(
        later - earlier == stride for earlier, later in zip(offsets, offsets[1:])
    ) else None


def fields_fit_record(
    prefix_length: int, stride: int, fields: Sequence[tuple[int, int]],
) -> bool:
    """Check absolute first-record offsets and widths against one record."""
    return all(
        offset >= prefix_length and offset - prefix_length + width <= stride
        for offset, width in fields
    )
