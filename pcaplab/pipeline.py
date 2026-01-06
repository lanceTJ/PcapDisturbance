# pcaplab/pipeline.py

from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import dpkt

from .core import Record, Stage
from .rule_matcher import YamlRulePacketMatcher
from .match import AttackMatcher, parse_time_ranges
from .stages import (
    DropStage,
    RetransmitStage,
    LengthForgeStage,
    LengthForgeTM2Stage,
    ReorderStage,
    RateAdjustStage,
    OnlineTimeSorter,
    SeqOffsetStage,
)
from .stream import _sniff_kind, stream_pcap_packets_fast
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


def _build_matcher(params: Dict[str, Any]):
    """
    New semantics:
      params.match is a YAML rules file path (string), or:
        match:
          rules_path: "/path/to/cic2018_improved_rules.yaml"
          include_labels: ["Botnet Ares", ...]   # optional

    Returns:
      YamlRulePacketMatcher or None
    """
    m = params.get("match")
    if not m:
        return None

    if isinstance(m, str):
        return YamlRulePacketMatcher(rules_path=m)

    if isinstance(m, dict):
        path = m.get("rules_path") or m.get("path") or m.get("yaml")
        if not path:
            raise ValueError("match dict requires rules_path/path/yaml")
        include_labels = m.get("include_labels")
        return YamlRulePacketMatcher(rules_path=str(path), include_labels=include_labels)

    raise ValueError(f"Unsupported match type: {type(m)}")
    return AttackMatcher(time_ranges=tr, ips=ips, match_on=ip_match)


# -----------------------------
# RNG derivation (fixes coupling)
# -----------------------------

def _stable_tag_hash64(tag: str) -> int:
    """
    Stable 64-bit hash for tags (independent of Python's randomized hash seed).
    """
    h = hashlib.blake2b(tag.encode("utf-8"), digest_size=8)
    return int.from_bytes(h.digest(), "little")


def _derive_rng(master: random.Random, tag: str) -> random.Random:
    """
    Derive an independent RNG stream for each stage.
    - Uses master.getrandbits(64) to incorporate the run seed.
    - Mixes in a stable hash of the stage tag to avoid dependence on Python's hash randomization.
    """
    seed64 = master.getrandbits(64) ^ _stable_tag_hash64(tag)
    return random.Random(seed64)


def compile_plan_to_stages(plan: List[dict], master_rng: random.Random) -> List[Stage]:
    stages: List[Stage] = []

    for i, step in enumerate(plan):
        t = str(step.get("type", "")).lower()
        pct = float(step.get("pct", 0.0))
        params = step.get("params", {}) or {}

        stage_rng = _derive_rng(master_rng, f"{i}:{t}")

        if t == "loss":
            stages.append(DropStage(pct=pct, rng=stage_rng))

        elif t in {"retrans", "retransmit"}:
            copies = int(params.get("copies", 1))
            delay_ms = float(params.get("delay_ms", 0.0))
            stages.append(RetransmitStage(pct=pct, copies=copies, delay_ms=delay_ms, rng=stage_rng))

        elif t in {"length_forge", "length-forge", "lenfake"}:
            strategy = str(params.get("strategy", "fixed")).lower().strip()
            pad_byte = _parse_pad_byte(params.get("pad_byte", "00"))
            matcher = _build_matcher(params)  # YAML matcher (optional)

            debug = bool(params.get("debug", False))
            debug_samples = int(params.get("debug_samples", 5))

            if strategy in {"tm2", "benign_pool", "pool"}:
                pool_mode = str(params.get("pool_mode", "auto"))
                benign_name_keywords = params.get("benign_name_keywords", ["benign", "normal"])
                min_len = int(params.get("min_len", 60))
                max_len = int(params.get("max_len", 1514))

                stages.append(
                    LengthForgeTM2Stage(
                        forge_ratio=pct,
                        pad_byte=pad_byte,
                        rng=stage_rng,
                        matcher=matcher,
                        pool_mode=pool_mode,
                        benign_name_keywords=list(benign_name_keywords),
                        min_len=min_len,
                        max_len=max_len,
                        debug=debug,
                        debug_samples=debug_samples,
                    )
                )
            else:
                # Backward-compatible fixed-length forge
                new_len = int(params.get("new_len"))
                stages.append(
                    LengthForgeStage(
                        pct=pct,
                        new_len=new_len,
                        pad_byte=pad_byte,
                        rng=stage_rng,
                        matcher=matcher,
                        debug=debug,
                        debug_samples=debug_samples,
                    )
                )

        elif t in {"reorder", "jitter"}:
            k = int(params.get("k", params.get("m", 5)))
            ts_mode = str(params.get("ts_mode", "keep")).lower()
            stages.append(ReorderStage(pct=pct, k=k, rng=stage_rng, ts_mode=ts_mode))

        elif t == "seq_offset":
            offset = int(params.get("offset", 1000))
            stages.append(SeqOffsetStage(pct=pct, rng=stage_rng, offset=offset))

        elif t in {"rate", "rate_adjust", "speed", "delay"}:
            matcher = _build_matcher(params)
            if matcher is None:
                raise ValueError("rate_adjust requires params.match as YAML rules path (string) or dict")
            shift_ms = float(params.get("shift_ms", params.get("s_ms", 0.0)))
            max_delay_ms = float(params.get("max_delay_ms", shift_ms))
            if max_delay_ms < shift_ms:
                raise ValueError("max_delay_ms must be >= shift_ms for OnlineTimeSorter correctness")

            stages.append(RateAdjustStage(pct=pct, shift_ms=shift_ms, rng=stage_rng, matcher=matcher))
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
    workflow_benign_sampler=None,
):
    """
    Stream records from in_pcap, apply stage pipeline, write to out_pcap.
    """
    py_seed = _mix_seed(selection_seed, in_pcap)
    master_rng = random.Random(py_seed)
    stats = defaultdict(int)

    # detect linktype
    with open(in_pcap, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        linktype = reader.datalink()

    kind = _sniff_kind(in_pcap)
    if kind != "pcap":
        raise ValueError("Current pipeline supports classic pcap only (pcapng not supported).")

    stages = compile_plan_to_stages(perturb_plan, master_rng)
    for st in stages:
        if st.__class__.__name__ == "LengthForgeTM2Stage":
            st.prepare(in_pcap=in_pcap, workflow_sampler=workflow_benign_sampler)

    out_f = open(out_pcap, "wb")
    writer = dpkt.pcap.Writer(out_f, linktype=linktype)

    total_in = 0
    total_out = 0

    def push_downstream(recs: List[Record]) -> List[Record]:
        nonlocal stats
        for st in stages:
            nxt: List[Record] = []
            for r in recs:
                nxt.extend(list(st.feed(r)))
            recs = nxt
        return recs

    try:
        buf: List[Tuple[float, bytes, int]] = []

        for idx, (ts, pkt) in enumerate(stream_pcap_packets_fast(in_pcap)):
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
