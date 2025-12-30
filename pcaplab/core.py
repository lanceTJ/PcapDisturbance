# pcaplab/core.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, List

@dataclass(frozen=True)
class Record:
    ts: float
    buf: bytes
    idx: int  # input order index

class Stage:
    """
    Streaming stage. feed() yields 0..N output records.
    flush() yields buffered tail records when input ends.
    """
    def feed(self, rec: Record) -> Iterable[Record]:
        yield rec

    def flush(self) -> Iterable[Record]:
        return []
