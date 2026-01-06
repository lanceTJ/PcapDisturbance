# pcaplab/length_pool.py
# -*- coding: utf-8 -*-

from __future__ import annotations

import bisect
import hashlib
import random
from dataclasses import dataclass
from typing import List, Optional
import math
from hashlib import blake2b


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


class GaussianLengthSampler:
    """
    Deterministic Gaussian sampler fitted from benign packet lengths.
    - ingest_len(): collect benign lengths (Welford)
    - finalize(): compute mu/sigma
    - sample_for_index(i): deterministic N(mu, sigma) draw, then clipped to [min_len, max_len]
    """

    def __init__(self, min_len: int = 60, max_len: int = 1514, seed: int = 0, sigma_floor: float = 1.0):
        self.min_len = int(min_len)
        self.max_len = int(max_len)
        self.seed = int(seed)
        self.sigma_floor = float(sigma_floor)

        # Welford accumulators
        self._n = 0
        self._mean = 0.0
        self._m2 = 0.0

        # fitted params
        self.mu = None
        self.sigma = None

    @property
    def total(self) -> int:
        return int(self._n)

    def ingest_len(self, L: int) -> None:
        x = float(L)
        if x < self.min_len or x > self.max_len:
            return
        self._n += 1
        delta = x - self._mean
        self._mean += delta / self._n
        delta2 = x - self._mean
        self._m2 += delta * delta2

    def finalize(self) -> None:
        if self._n <= 1:
            self.mu = float(self._mean) if self._n == 1 else float(self.min_len)
            self.sigma = float(self.sigma_floor)
            return

        var = self._m2 / (self._n - 1)
        sigma = math.sqrt(max(var, 0.0))
        self.mu = float(self._mean)
        self.sigma = float(max(sigma, self.sigma_floor))

    def _u01_pair(self, idx: int) -> tuple[float, float]:
        # Deterministic 2 uniforms from hash(seed, idx)
        h = blake2b(digest_size=16)
        h.update(str(self.seed).encode("utf-8"))
        h.update(b":")
        h.update(str(idx).encode("utf-8"))
        d = h.digest()
        a = int.from_bytes(d[:8], "little")
        b = int.from_bytes(d[8:], "little")

        # map to (0,1)
        u1 = (a + 1) / (2**64 + 2)
        u2 = (b + 1) / (2**64 + 2)
        return u1, u2

    def sample_for_index(self, idx: int) -> int:
        if self.mu is None or self.sigma is None:
            raise RuntimeError("GaussianLengthSampler not finalized")

        u1, u2 = self._u01_pair(idx)

        # Box-Muller -> standard normal
        z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
        x = self.mu + self.sigma * z

        # clip to valid range
        L = int(round(x))
        if L < self.min_len: L = self.min_len
        if L > self.max_len: L = self.max_len
        return L