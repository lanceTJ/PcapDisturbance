# pcaplab/length_pool.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import bisect
import hashlib
import random
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class BenignLengthSampler:
    """
    Empirical sampler for frame lengths using histogram counts on [min_len, max_len].

    - Memory O(bins): only counts and prefix sums (typically ~1500 bins).
    - Deterministic per-index sampling to avoid order/copy dependence.

    Deterministic sampling:
      sample_for_index(i) uses a stable hash of (seed, i) to generate u in [0, total),
      then maps u to a length via prefix sums.
    """
    min_len: int = 60
    max_len: int = 1514
    seed: int = 2026

    def __post_init__(self) -> None:
        if self.min_len >= self.max_len:
            raise ValueError("min_len must be < max_len")
        self._counts: List[int] = [0] * (self.max_len - self.min_len + 1)
        self._prefix: Optional[List[int]] = None
        self._total: int = 0

    @property
    def total(self) -> int:
        return self._total

    def ingest_len(self, frame_len: int) -> None:
        """Add one observed benign frame length into the histogram."""
        if self.min_len <= frame_len <= self.max_len:
            self._counts[frame_len - self.min_len] += 1
            self._total += 1

    def finalize(self) -> None:
        """Build prefix sums for sampling. Must be called once after ingestion."""
        if self._total <= 0:
            raise ValueError("No lengths ingested; cannot finalize sampler.")
        s = 0
        prefix: List[int] = []
        for c in self._counts:
            s += c
            prefix.append(s)
        self._prefix = prefix

    def _map_u_to_len(self, u: int) -> int:
        """Map u in [0, total) to a length via prefix sums."""
        if self._prefix is None:
            raise RuntimeError("Sampler not finalized. Call finalize() first.")
        idx = bisect.bisect_right(self._prefix, u)
        return self.min_len + idx

    def sample(self, rng: random.Random) -> int:
        """
        Order-dependent sampling. Prefer sample_for_index for reproducibility when
        packet duplication/reordering can occur.
        """
        if self._total <= 0:
            raise RuntimeError("Sampler is empty.")
        u = rng.randrange(self._total)
        return self._map_u_to_len(u)

    def sample_for_index(self, index: int) -> int:
        """
        Deterministically sample a length for a given packet index.
        This avoids copy/order dependence (e.g., retransmitted copies with same idx).
        """
        if self._total <= 0:
            raise RuntimeError("Sampler is empty.")
        h = hashlib.blake2b(digest_size=8)
        h.update(str(self.seed).encode("utf-8"))
        h.update(b"||")
        h.update(str(int(index)).encode("utf-8"))
        u = int.from_bytes(h.digest(), "little") % self._total
        return self._map_u_to_len(u)
