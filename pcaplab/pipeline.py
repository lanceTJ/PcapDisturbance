# pcaplab/pipeline.py (replace most logic)
from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import dpkt

from .core import Record, Stage
from .match import AttackMatcher, parse_time_ranges
from .stages import (
    DropStage, RetransmitStage, LengthForgeStage, ReorderStage,
    RateAdjustStage, OnlineTimeSorter, SeqOffsetStage
)
from .stream import _sniff_kind, stream_pcap_packets, stream_pcap_packets_fast
from .utils import log


def _mix_seed(selection_seed: int, in_pcap: str) -> int:
    h = hashlib.blake2b(digest_size=8)
    h.update(str(selection_seed).encode("utf-8"))
    h.update(b"||")
    h.update(in_pcap.encode("utf-8"))
    return int.from_bytes(h.digest(), "little")


def _parse_pad_byte(pad_byte: Any) -> int:
    if pad_byte is None:
        return 0x00
    if isinstance(pad_byte, int):
        if 0 <= pad_byte <= 255:
            return pad_byte
        raise ValueError("pad_byte int must be 0..255")
    s = str(pad_byte).strip().lower()
    if s.startswith("0x"):
        v = int(s, 16)
    else:
        try:
            v = int(s, 10)
        except ValueError:
            v = int(s, 16)
    if not (0 <= v <= 255):
        raise ValueError("pad_byte must be 0..255")
    return v


def _build_matcher(params: Dict[str, Any]) -> Optional[AttackMatcher]:
    """
    Optional in params:
      match:
        time_ranges: ["start,end", ...]   # float seconds (pcap ts)
        ips: ["1.2.3.4", "2001:db8::1"]
        ip_match: "either"|"src"|"dst"
    """
    m = params.get("match")
    if not m:
        return None
    tr = parse_time_ranges(m.get("time_ranges", []))
    ips = set(m.get("ips", []))
    ip_match = m.get("ip_match", "either")
    return AttackMatcher(time_ranges=tr, ips=ips, match_on=ip_match)


def compile_plan_to_stages(plan: List[dict], rng: random.Random) -> List[Stage]:
    stages: List[Stage] = []

    for step in plan:
        t = str(step.get("type", "")).lower()
        pct = float(step.get("pct", 0.0))  # your config uses 0..1

        params = step.get("params", {}) or {}

        if t == "loss":
            stages.append(DropStage(pct=pct, rng=rng))

        elif t in {"retrans", "retransmit"}:
            copies = int(params.get("copies", 1))
            delay_ms = float(params.get("delay_ms", 0.0))
            stages.append(RetransmitStage(pct=pct, copies=copies, delay_ms=delay_ms, rng=rng))

        elif t in {"length_forge", "length-forge", "lenfake"}:
            new_len = int(params.get("new_len"))
            pad_byte = _parse_pad_byte(params.get("pad_byte", "00"))
            matcher = _build_matcher(params)
            stages.append(LengthForgeStage(pct=pct, new_len=new_len, pad_byte=pad_byte, rng=rng, matcher=matcher))

        elif t in {"reorder", "jitter"}:
            # align to your new spec: trigger with pct; shuffle k packets after trigger
            # keep compatibility: if user gives params.m (old), treat as k = m
            k = int(params.get("k", params.get("m", 5)))
            ts_mode = str(params.get("ts_mode", "keep")).lower()
            stages.append(ReorderStage(pct=pct, k=k, rng=rng, ts_mode=ts_mode))

        elif t == "seq_offset":
            offset = int(params.get("offset", 1000))
            stages.append(SeqOffsetStage(pct=pct, rng=rng, offset=offset))

        elif t in {"rate", "rate_adjust", "speed", "delay"}:
            # shift attack packets forward and then reorder by ts (bounded)
            matcher = _build_matcher(params)
            if matcher is None:
                raise ValueError("rate_adjust requires params.match")
            shift_ms = float(params.get("shift_ms", params.get("s_ms", 0.0)))
            max_delay_ms = float(params.get("max_delay_ms", shift_ms))
            if max_delay_ms < shift_ms:
                raise ValueError("max_delay_ms must be >= shift_ms for OnlineTimeSorter correctness")

            stages.append(RateAdjustStage(pct=pct, shift_ms=shift_ms, rng=rng, matcher=matcher))
            stages.append(OnlineTimeSorter(max_delay_ms=max_delay_ms))

        else:
            raise ValueError(f"Unknown perturbation type: {t}")

    return stages


def apply_perturbations_stream(
    in_pcap: str,
    out_pcap: str,
    perturb_plan: List[dict],
    selection_seed: int = 0,
    chunk_size: int = 10000,
    show_progress: bool = False,
    progress_every: int = 200_000,
):
    py_seed = _mix_seed(selection_seed, in_pcap)
    rng = random.Random(py_seed)
    stats = defaultdict(int)

    # detect linktype
    with open(in_pcap, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        linktype = reader.datalink()

    out_f = open(out_pcap, "wb")
    writer = dpkt.pcap.Writer(out_f, linktype=linktype)

    # choose stream
    kind = _sniff_kind(in_pcap)
    if kind != "pcap":
        raise ValueError("Current pipeline supports classic pcap only (pcapng not supported yet).")

    # fast stream always ok because our stages consume (ts, bytes)
    stream_func = stream_pcap_packets_fast

    stages = compile_plan_to_stages(perturb_plan, rng)

    total_in = 0
    total_out = 0

    def push_downstream(recs: List[Record]) -> List[Record]:
        nonlocal stats
        for st in stages:
            nxt: List[Record] = []
            for r in recs:
                out_iter = list(st.feed(r))
                nxt.extend(out_iter)
            recs = nxt
        return recs

    try:
        buf: List[Tuple[float, bytes, int]] = []
        for idx, (ts, pkt) in enumerate(stream_func(in_pcap)):
            buf.append((ts, pkt, idx))
            if len(buf) >= chunk_size:
                for ts0, pkt0, idx0 in buf:
                    total_in += 1
                    out_recs = push_downstream([Record(ts=ts0, buf=pkt0, idx=idx0)])
                    for r in out_recs:
                        writer.writepkt(r.buf, ts=r.ts)
                        total_out += 1
                if show_progress and total_in // progress_every != (total_in - len(buf)) // progress_every:
                    log.info(f"[progress] {in_pcap} in={total_in} out={total_out}")
                buf.clear()

        if buf:
            for ts0, pkt0, idx0 in buf:
                total_in += 1
                out_recs = push_downstream([Record(ts=ts0, buf=pkt0, idx=idx0)])
                for r in out_recs:
                    writer.writepkt(r.buf, ts=r.ts)
                    total_out += 1
            buf.clear()

        # flush stages (important for reorder/sorter)
        tail: List[Record] = []
        # stage-by-stage flush propagation
        for i, st in enumerate(stages):
            flushed = list(st.flush())
            if not flushed:
                continue
            recs = flushed
            for st2 in stages[i + 1 :]:
                nxt = []
                for r in recs:
                    nxt.extend(list(st2.feed(r)))
                recs = nxt
            for r in recs:
                writer.writepkt(r.buf, ts=r.ts)
                total_out += 1

        return {"total_in": total_in, "total_out": total_out, "stats": dict(stats)}

    finally:
        try:
            out_f.close()
        except Exception:
            pass
