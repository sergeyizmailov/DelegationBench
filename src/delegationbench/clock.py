"""Virtual clock for deterministic runs.

Time is seconds since t0 (run start). Nothing in the package reads the
wall clock; rules advance this clock explicitly (``advance_clock``) so
expiry attacks are reproducible.
"""

from __future__ import annotations


class VirtualClock:
    def __init__(self) -> None:
        self.now: float = 0.0

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot advance clock by a negative amount")
        self.now += seconds
