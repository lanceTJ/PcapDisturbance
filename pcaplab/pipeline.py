# pcaplab/pipeline.py
from __future__ import annotations
import random, hashlib
from collections import defaultdict
from typing import List, Tuple
import numpy as np
from scapy.all import Ether  # 仅在需要修改内容时才用到

from .stream import stream_pcap_packets
from .io import PcapSinkBuffered
from .utils import log

NEED_PARSE_OPS = {"length_forge", "seq_offset"}

def _plan_needs_parse(plan: List[dict]) -> bool:
    return any(str(s.get("type", "")).lower() in NEED_PARSE_OPS for s in plan)

def _select_indices(plan: List[dict], n: int, rng: np.random.Generator, stats: dict) -> np.ndarray:
    """
    向量化选择：返回保留/复制/乱序后的索引数组。
    """
    idx = np.arange(n, dtype=np.int64)
    for step in plan:
        t = str(step.get("type", "")).lower()
        if t == "loss":
            p = float(step.get("pct", 0.0))
            keep = rng.random(idx.size) >= p
            stats["loss_drop"] += int((~keep).sum())
            idx = idx[keep]
        elif t in {"retrans", "retransmit"}:
            p = float(step.get("pct", 0.0))
            dup = rng.random(idx.size) < p
            stats["retransmit_dup"] += int(dup.sum())
            if dup.any():
                idx = np.concatenate([idx, idx[dup]])
        elif t in {"reorder", "jitter"}:
            rng.shuffle(idx)
        # 其余类型在“选择阶段”不动（length_forge/seq_offset 留给修改阶段）
    return idx

def _process_chunk(
    buf: List[Tuple[bytes, int, int]],  # (pkt_bytes, ts_sec, ts_usec)
    sink: PcapSinkBuffered,
    plan: List[dict],
    py_rng: random.Random,              # 仍保留，以便你有零星需要
    stats: dict
) -> Tuple[int, int]:
    """
    零解析快路径：不需要改包体 -> 直接 write_raw。
    需要改包体 -> 仅对“被选中”的索引解析并修改，然后写出。
    """
    n = len(buf)
    if n == 0:
        return 0, 0

    # 选择阶段（纯索引运算）
    np_seed = py_rng.getrandbits(64)
    np_rng = np.random.default_rng(np_seed)  # 用 np_seed 作为种子推进
    sel = _select_indices(plan, n, np_rng, stats)
    total_in = n
    total_out = 0

    if not _plan_needs_parse(plan):
        # 快路径：直接写原始字节 + ts
        for i in sel:
            pkt_bytes, ts_sec, ts_usec = buf[int(i)]
            sink.write_raw(ts_sec, ts_usec, pkt_bytes)
        return total_in, int(sel.size)

    # 需要修改：仅对命中索引解析，修改后写出
    for i in sel:
        pkt_bytes, ts_sec, ts_usec = buf[int(i)]
        pkt = Ether(pkt_bytes)  # 只解析命中子集
        for step in plan:
            t = str(step.get("type", "")).lower()
            if t == "seq_offset":
                off = int(step.get("params", {}).get("offset", 0))
                if pkt.haslayer("TCP"):
                    pkt["TCP"].seq = (int(pkt["TCP"].seq) + off) & 0xFFFFFFFF
                    # 让 scapy 重新计算校验和
                    if pkt.haslayer("IP"):
                        del pkt["IP"].chksum
                    if pkt.haslayer("TCP"):
                        del pkt["TCP"].chksum
            elif t == "length_forge":
                new_len = int(step.get("params", {}).get("new_len", len(pkt)))
                raw = bytes(pkt)
                if len(raw) > new_len:
                    raw = raw[:new_len]
                elif len(raw) < new_len:
                    raw = raw + b"\x00" * (new_len - len(raw))
                pkt = Ether(raw)
        # 解析路径下也沿用 buffered raw 写：从 pkt 重新导出 bytes
        sink.write_raw(ts_sec, ts_usec, bytes(pkt))
        total_out += 1

    return total_in, total_out

def _mix_seed(selection_seed: int, in_pcap: str) -> int:
    # 用 blake2b(file_path, seed) 生成稳定 64-bit 种子
    h = hashlib.blake2b(digest_size=8)
    h.update(str(selection_seed).encode('utf-8'))
    h.update(b'||')
    h.update(in_pcap.encode('utf-8'))
    return int.from_bytes(h.digest(), 'little')

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
    sink = PcapSinkBuffered(out_pcap)
    total_in = total_out = 0
    stats = defaultdict(int)

    buf: List[Tuple[bytes, int, int]] = []

    try:
        for pkt_bytes, ts_sec, ts_usec in stream_pcap_packets(in_pcap):
            buf.append((pkt_bytes, ts_sec, ts_usec))
            if len(buf) >= chunk_size:
                _in, _out = _process_chunk(buf, sink, perturb_plan, rng, stats)
                total_in += _in; total_out += _out
                if show_progress and total_in // progress_every != (total_in - _in) // progress_every:
                    log.info(f"[progress] {in_pcap}  in={total_in} out={total_out}")
                buf.clear()

        if buf:
            _in, _out = _process_chunk(buf, sink, perturb_plan, rng, stats)
            total_in += _in; total_out += _out
            if show_progress:
                log.info(f"[progress] {in_pcap}  in={total_in} out={total_out}")
    finally:
        try:
            sink.close()
        except Exception:
            pass

    return {"total_in": total_in, "total_out": total_out, "stats": dict(stats)}
