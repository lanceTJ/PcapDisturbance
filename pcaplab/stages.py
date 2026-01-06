# pcaplab/stages.py
from __future__ import annotations

import dataclasses
import heapq
import ipaddress
import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Deque, Iterable, List, Optional, Tuple, Any
from collections import deque

import dpkt

from .core import Record, Stage
from .match import AttackMatcher
from .rule_matcher import YamlRulePacketMatcher
from .perturbations import perturb_length_forge_l3aware
from .utils import log


def parse_l3_addrs(buf: bytes) -> Tuple[Optional[str], Optional[str], str]:
    """
    Best-effort parse Ethernet(+VLAN) -> IPv4/IPv6 addrs.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        payload = eth.data
        if isinstance(payload, dpkt.ethernet.VLANtag8021Q):
            payload = payload.data

        if isinstance(payload, dpkt.ip.IP):
            src = str(ipaddress.IPv4Address(payload.src))
            dst = str(ipaddress.IPv4Address(payload.dst))
            return src, dst, "ipv4"

        if isinstance(payload, dpkt.ip6.IP6):
            src = str(ipaddress.IPv6Address(payload.src))
            dst = str(ipaddress.IPv6Address(payload.dst))
            return src, dst, "ipv6"

        return None, None, "none"
    except Exception:
        return None, None, "none"


def fixed_len_bytes(buf: bytes, new_len: int, pad_byte: int) -> bytes:
    if new_len < 0:
        raise ValueError("new_len must be >= 0")
    if len(buf) >= new_len:
        return buf[:new_len]
    return buf + bytes([pad_byte]) * (new_len - len(buf))

def _match_label(matcher: Any, rec: Record) -> Optional[str]:
    if matcher is None:
        return None
    fn = getattr(matcher, "match_first_label", None)
    if callable(fn):
        return fn(rec.ts, rec.buf)
    fn2 = getattr(matcher, "match_packet", None)
    if callable(fn2):
        return "__matched__" if fn2(rec.ts, rec.buf) else None
    raise TypeError(f"Unsupported matcher type: {type(matcher)}")

def _match_packet(matcher: Any, rec: Record) -> bool:
    """
    matcher compatibility layer:
      - YamlRulePacketMatcher: matcher.match_packet(ts, buf)
      - legacy AttackMatcher: matcher.is_attack(ts, src_ip, dst_ip) requires L3 parse (not used here)
    """
    if matcher is None:
        return True
    mp = getattr(matcher, "match_packet", None)
    if callable(mp):
        return bool(mp(rec.ts, rec.buf))
    raise TypeError(f"Unsupported matcher type: {type(matcher)}")

@dataclass
class DropStage(Stage):
    pct: float  # 0..1
    rng: random.Random

    def feed(self, rec: Record) -> Iterable[Record]:
        if self.rng.random() < self.pct:
            return []
        return [rec]


@dataclass
class RetransmitStage(Stage):
    pct: float  # 0..1
    copies: int
    delay_ms: float
    rng: random.Random

    def feed(self, rec: Record) -> Iterable[Record]:
        out = [rec]
        if self.copies > 0 and self.rng.random() < self.pct:
            base = rec.ts
            step = self.delay_ms / 1000.0
            for i in range(1, self.copies + 1):
                out.append(Record(ts=base + i * step, buf=rec.buf, idx=rec.idx))
        return out


@dataclass
class LengthForgeStage(Stage):
    pct: float
    new_len: int
    pad_byte: int
    rng: random.Random
    matcher: Optional[Any] = None

    # debug knobs
    debug: bool = False
    debug_samples: int = 5

    # counters
    seen: int = 0
    matched: int = 0
    matched_but_skipped_by_pct: int = 0
    applied: int = 0
    padded: int = 0
    truncated: int = 0
    unchanged_already_len: int = 0

    label_counter: Counter = field(default_factory=Counter)
    sample_lines: List[str] = field(default_factory=list)

    def feed(self, rec: Record) -> Iterable[Record]:
        self.seen += 1

        label = None
        if self.matcher is not None:
            label = _match_label(self.matcher, rec)
            if label is None:
                if self.debug and len(self.sample_lines) < self.debug_samples:
                    self.sample_lines.append(f"[MISS] ts={rec.ts:.6f} len={len(rec.buf)}")
                return [rec]

        # matched (or matcher is None)
        if self.matcher is not None:
            self.matched += 1
            self.label_counter[label] += 1

        # pct gate
        if self.rng.random() >= self.pct:
            if self.matcher is not None:
                self.matched_but_skipped_by_pct += 1
            if self.debug and len(self.sample_lines) < self.debug_samples:
                self.sample_lines.append(f"[SKIP_PCT] ts={rec.ts:.6f} len={len(rec.buf)} label={label}")
            return [rec]

        # apply
        old_len = len(rec.buf)
        nb = perturb_length_forge_l3aware(rec.buf, new_len=self.new_len, pad_byte=self.pad_byte)
        new_len = len(nb)

        self.applied += 1
        if old_len < self.new_len:
            self.padded += 1
        elif old_len > self.new_len:
            self.truncated += 1
        else:
            self.unchanged_already_len += 1

        if self.debug and len(self.sample_lines) < self.debug_samples:
            self.sample_lines.append(
                f"[APPLY] ts={rec.ts:.6f} {old_len}->{new_len} label={label}"
            )

        return [Record(ts=rec.ts, buf=nb, idx=rec.idx)]

    def flush(self) -> Iterable[Record]:
        if self.debug:
            top_labels = self.label_counter.most_common(10)
            log.info(
                "[length_forge debug] "
                f"seen={self.seen} matched={self.matched} "
                f"skipped_by_pct={self.matched_but_skipped_by_pct} applied={self.applied} "
                f"padded={self.padded} truncated={self.truncated} unchanged_len={self.unchanged_already_len}"
            )
            if top_labels:
                log.info("[length_forge debug] top labels: " + ", ".join([f"{k}:{v}" for k, v in top_labels]))
            for line in self.sample_lines:
                log.info("[length_forge debug] " + line)
        return []


@dataclass
class ReorderStage(Stage):
    """
    Trigger with probability pct (0..1). When triggered at a packet, buffer it + next k packets,
    shuffle them, then reassign timestamps to keep monotonicity in the window.
    """
    pct: float
    k: int
    rng: random.Random
    ts_mode: str = "keep"  # keep|linear
    _buf: Deque[Record] = dataclasses.field(default_factory=deque, init=False)
    _need: int = dataclasses.field(default=0, init=False)

    def feed(self, rec: Record) -> Iterable[Record]:
        if self._need > 0:
            self._buf.append(rec)
            self._need -= 1
            if self._need == 0:
                return self._emit()
            return []

        if self.k > 0 and self.rng.random() < self.pct:
            self._buf.append(rec)
            self._need = self.k
            return []
        return [rec]

    def _emit(self) -> List[Record]:
        window = list(self._buf)
        self._buf.clear()

        if len(window) <= 1:
            return window

        orig_ts = [r.ts for r in window]
        ts_sorted = sorted(orig_ts)

        self.rng.shuffle(window)

        if self.ts_mode == "keep":
            return [Record(ts=ts_sorted[i], buf=window[i].buf, idx=window[i].idx) for i in range(len(window))]

        if self.ts_mode == "linear":
            t0, t1 = min(orig_ts), max(orig_ts)
            if t1 <= t0 or len(window) == 1:
                return [Record(ts=t0, buf=window[0].buf, idx=window[0].idx)]
            step = (t1 - t0) / (len(window) - 1)
            return [Record(ts=t0 + i * step, buf=window[i].buf, idx=window[i].idx) for i in range(len(window))]

        return window

    def flush(self) -> Iterable[Record]:
        if self._buf:
            # emit as-is (or you can still shuffle; I建议 as-is 更保守)
            out = list(self._buf)
            self._buf.clear()
            self._need = 0
            return out
        return []


@dataclass(order=True)
class _HeapItem:
    ts: float
    idx: int
    buf: bytes = dataclasses.field(compare=False)


@dataclass
class OnlineTimeSorter(Stage):
    """
    Online sorter for bounded forward delay.
    Assumption: timestamps are only shifted forward by <= max_delay_ms.
    """
    max_delay_ms: float
    _heap: List[_HeapItem] = dataclasses.field(default_factory=list, init=False)
    _last_in_ts: float = dataclasses.field(default=float("-inf"), init=False)

    def feed(self, rec: Record) -> Iterable[Record]:
        self._last_in_ts = rec.ts
        heapq.heappush(self._heap, _HeapItem(ts=rec.ts, idx=rec.idx, buf=rec.buf))

        watermark = self._last_in_ts - (self.max_delay_ms / 1000.0)
        out: List[Record] = []
        while self._heap and self._heap[0].ts <= watermark:
            it = heapq.heappop(self._heap)
            out.append(Record(ts=it.ts, buf=it.buf, idx=it.idx))
        return out

    def flush(self) -> Iterable[Record]:
        out: List[Record] = []
        while self._heap:
            it = heapq.heappop(self._heap)
            out.append(Record(ts=it.ts, buf=it.buf, idx=it.idx))
        return out


@dataclass
class RateAdjustStage(Stage):
    """
    Attack packets: with probability pct, shift timestamp forward by shift_ms.
    Reposition should be done by a downstream OnlineTimeSorter stage.
    """
    pct: float  # 0..1
    shift_ms: float
    rng: random.Random
    matcher: Any  # <- required, typically YamlRulePacketMatcher

    def feed(self, rec: Record) -> Iterable[Record]:
        if _match_packet(self.matcher, rec) and self.rng.random() < self.pct:
            return [Record(ts=rec.ts + self.shift_ms / 1000.0, buf=rec.buf, idx=rec.idx)]
        return [rec]


# ---- seq_offset wrapper: reuse your existing function (bytes -> bytes) ----

@dataclass
class SeqOffsetStage(Stage):
    pct: float  # 0..1
    rng: random.Random
    offset: int

    def feed(self, rec: Record) -> Iterable[Record]:
        if self.rng.random() >= self.pct:
            return [rec]
        # late import to avoid overhead if unused
        from .perturbations import perturb_seq_offset
        nb = perturb_seq_offset(rec.buf, offset=self.offset)
        return [Record(ts=rec.ts, buf=nb, idx=rec.idx)]
