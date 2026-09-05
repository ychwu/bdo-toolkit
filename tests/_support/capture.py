"""Small capture values and controllable threads; race scenarios stay local."""

from bdo_toolkit import BDOEvent, Flow


def item_event(item_id: int) -> BDOEvent:
    return BDOEvent(
        event_type="item_received",
        timestamp=float(item_id),
        flow=Flow("203.0.113.1", 8889, "198.51.100.2", 50000),
        item_id=item_id,
        quantity=1,
    )


class ControlledThread:
    def __init__(self, *, alive: bool = True) -> None:
        self.ident = 1234
        self.alive = alive
        self.join_calls: list[float | None] = []

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float | None = None) -> None:
        self.join_calls.append(timeout)
