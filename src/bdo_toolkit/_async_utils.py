"""Cancellation-safe waits shared by asynchronous session facades."""

import asyncio


async def _wait_ignoring_cancellation[T](future: asyncio.Future[T]) -> T:
    """Wait for an already-started operation, even after caller cancellation."""

    while not future.done():
        try:
            # asyncio.wait() never propagates cancellation into ``future`` and
            # does not create a cancelled shield wrapper that may later log an
            # otherwise-retrieved worker exception on Python 3.14.
            await asyncio.wait((future,))
        except asyncio.CancelledError:
            # Cleanup must settle before the original cancellation escapes.
            continue
    return future.result()


async def _await_preserving_future[T](future: asyncio.Future[T]) -> T:
    """Await without cancelling or wrapping the submitted worker future."""

    await asyncio.wait((future,))
    return future.result()
