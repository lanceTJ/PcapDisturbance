# pcaplab/stages.py
from __future__ import annotations

import os
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
from .length_pool import BenignLengthSampler
from .stream import stream_pcap_packets_fast
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
class LengthForgeTM2Stage(Stage):
    """
    TM-II length forgery (benign-pool sampling) with exact forge ratio on attack packets.

    Preparation step (two-pass per pcap):
    - Mixed pcap (matcher provided): pass1 builds benign pool from non-matched packets and collects attack indices.
    - Attack-only pcap (matcher None): pass1 counts packets only; benign pool is provided as workflow_sampler.
      Benign pcaps are auto-detected by filename keywords and are left unchanged.

    Runtime step (pass2 streaming):
    - If rec.idx is in selected forge_set, replace length using benign sampler (deterministic per idx).
    """

    forge_ratio: float  # 0..1
    pad_byte: int
    rng: random.Random
    matcher: Optional[Any] = None

    # pool controls
    pool_mode: str = "auto"  # auto|self|workflow
    benign_name_keywords: List[str] = field(default_factory=lambda: ["benign", "normal"])

    # benign pool binning
    min_len: int = 60
    max_len: int = 1514

    # debug
    debug: bool = False
    debug_samples: int = 5

    # prepared artifacts
    _prepared: bool = field(default=False, init=False)
    _sampler: Optional[BenignLengthSampler] = field(default=None, init=False)
    _forge_set: set[int] = field(default_factory=set, init=False)

    # stats
    seen: int = 0
    attack_cnt: int = 0
    forge_cnt: int = 0
    applied: int = 0
    skipped_non_attack_pcap: int = 0
    skipped_no_pool: int = 0

    sample_lines: List[str] = field(default_factory=list)

    def prepare(self, in_pcap: str, workflow_sampler: Optional[BenignLengthSampler] = None) -> None:
        """
        Pre-scan input pcap to build pool / select exact forge indices.
        Must be called BEFORE streaming pass2 begins.
        """
        if not (0.0 <= self.forge_ratio <= 1.0):
            raise ValueError("forge_ratio must be within [0, 1]")

        base = os.path.basename(in_pcap).lower()

        # Determine pool mode
        mode = self.pool_mode.lower().strip()
        if mode == "auto":
            mode = "self" if self.matcher is not None else "workflow"

        # Case A: matcher provided -> mixed pcap, build pool from non-matched packets
        if self.matcher is not None and mode == "self":
            sampler_seed = int(self.rng.getrandbits(32))
            sampler = BenignLengthSampler(min_len=self.min_len, max_len=self.max_len, seed=sampler_seed)
            attack_indices: List[int] = []

            for idx, (ts, pkt) in enumerate(stream_pcap_packets_fast(in_pcap)):
                is_attack = bool(getattr(self.matcher, "match_packet")(ts, pkt))
                if is_attack:
                    attack_indices.append(idx)
                else:
                    sampler.ingest_len(len(pkt))

            sampler.finalize()

            self.attack_cnt = len(attack_indices)
            k = int(round(self.attack_cnt * self.forge_ratio))
            self._forge_set = set(self.rng.sample(attack_indices, k=k)) if k > 0 else set()
            self.forge_cnt = len(self._forge_set)
            self._sampler = sampler
            self._prepared = True
            return

        # Case B: no matcher -> file-level benign/attack by name, use workflow sampler
        if self.matcher is None and mode == "workflow":
            is_benign_pcap = any(kw.lower() in base for kw in (self.benign_name_keywords or []))
            if is_benign_pcap:
                # This pcap should remain unchanged under TM2.
                self._forge_set = set()
                self._sampler = workflow_sampler
                self.skipped_non_attack_pcap += 1
                self._prepared = True
                return

            if workflow_sampler is None or workflow_sampler.total <= 0:
                self.skipped_no_pool += 1
                raise ValueError(
                    "TM2 length_forge requires a workflow benign pool when matcher is None. "
                    "Build it once in batch runner and pass workflow_sampler into apply_perturbations_stream()."
                )

            # Count packets only (attack_cnt == total packets)
            total = 0
            for _ts, _pkt in stream_pcap_packets_fast(in_pcap):
                total += 1

            self.attack_cnt = total
            k = int(round(self.attack_cnt * self.forge_ratio))
            self._forge_set = set(self.rng.sample(range(total), k=k)) if k > 0 else set()
            self.forge_cnt = len(self._forge_set)
            self._sampler = workflow_sampler
            self._prepared = True
            return

        raise ValueError(f"Unsupported TM2 pool_mode={self.pool_mode} with matcher={self.matcher is not None}")

    def feed(self, rec: Record) -> Iterable[Record]:
        if not self._prepared:
            raise RuntimeError("LengthForgeTM2Stage not prepared. Call prepare() before streaming.")

        self.seen += 1
        if rec.idx not in self._forge_set:
            return [rec]

        if self._sampler is None:
            raise RuntimeError("TM2 sampler is missing after preparation.")

        # Deterministic per-index sampling to avoid copy/order dependence.
        target_len = self._sampler.sample_for_index(rec.idx)

        nb = perturb_length_forge_l3aware(rec.buf, new_len=target_len, pad_byte=self.pad_byte)
        self.applied += 1

        if self.debug and len(self.sample_lines) < self.debug_samples:
            self.sample_lines.append(
                f"[TM2_APPLY] idx={rec.idx} ts={rec.ts:.6f} {len(rec.buf)}->{len(nb)} target_len={target_len}"
            )

        return [Record(ts=rec.ts, buf=nb, idx=rec.idx)]

    def flush(self) -> Iterable[Record]:
        if self.debug:
            log.info(
                "[length_forge_tm2 debug] "
                f"seen={self.seen} attack_cnt={self.attack_cnt} forge_cnt={self.forge_cnt} applied={self.applied} "
                f"skipped_benign_pcap={self.skipped_non_attack_pcap} skipped_no_pool={self.skipped_no_pool}"
            )
            for line in self.sample_lines:
                log.info("[length_forge_tm2 debug] " + line)
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
