# pcaplab/pipeline.py
from __future__ import annotations
import random, hashlib
from collections import defaultdict
from typing import List, Tuple, Dict
import numpy as np
import struct
from scapy.all import Ether, IP, TCP, UDP, Raw  # Import for modifications
from scapy.packet import Packet

from .stream import stream_pcap_packets, stream_raw_pcap_records, _sniff_kind
from .io import PcapSinkBuffered
from .utils import log
from .perturbations import PERTURBATIONS  # Import perturbation functions

NEED_PARSE_OPS = {"length_forge", "seq_offset"}

def _plan_needs_parse(plan: List[dict]) -> bool:
    return any(str(s.get("type", "")).lower() in NEED_PARSE_OPS for s in plan)

def _extract_ts_from_raw_records(buf: List[bytes]) -> Tuple[np.ndarray, np.ndarray, callable]:
    """
    Extract ts_sec/ts_usec from raw records. Auto-detect endian from first record.
    Return (ts_sec_arr, ts_usec_arr), and patch function.
    """
    if not buf:
        raise ValueError("Empty buffer")
    first_hdr = buf[0][0:16]
    try:
        ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", first_hdr)
        fmt = "<II"
        little = True
    except struct.error:
        ts_sec, ts_usec, incl, orig = struct.unpack(">IIII", first_hdr)
        fmt = ">II"
        little = False
    hdr_len = 16

    ts_sec_list = []
    ts_usec_list = []
    for rec in buf:
        s, u = struct.unpack(fmt, rec[0:8])
        ts_sec_list.append(s)
        ts_usec_list.append(u)

    def patch_ts(raw: bytes, new_sec: int, new_usec: int) -> bytes:
        b = bytearray(raw)
        b[0:8] = struct.pack(fmt + "II", int(new_sec), int(new_usec), len(raw) - hdr_len, len(raw) - hdr_len)
        return bytes(b)

    return (np.array(ts_sec_list, dtype=np.int64),
            np.array(ts_usec_list, dtype=np.int64),
            patch_ts)

def _select_indices_and_ts_perm(
    plan: List[dict], n: int, rng: np.random.Generator, stats: dict
) -> Tuple[np.ndarray, Dict[int, int]]:
    """Same as original, no change."""
    idx = np.arange(n, dtype=np.int64)
    ts_perm_map: Dict[int, int] = {i: i for i in range(n)}

    for step in plan:
        t = str(step.get("type", "")).lower()

        if t == "loss":
            p = float(step.get("pct", 0.0))
            keep = rng.random(idx.size) >= p
            stats["loss_drop"] = int((~keep).sum())
            idx = idx[keep]

        elif t in {"retrans", "retransmit"}:
            p = float(step.get("pct", 0.0))
            dup = rng.random(idx.size) < p
            stats["retransmit_dup"] = int(dup.sum())
            if dup.any():
                idx = np.concatenate([idx, idx[dup]])

        elif t in {"reorder", "jitter"}:
            p = float(step.get("pct", 0.0))
            params = step.get("params", {}) or {}
            m = int(params.get("m", 5))

            if p > 0 and idx.size > 2:
                used = np.zeros(idx.size, dtype=bool)
                reorder_count = 0

                for start in rng.permutation(np.arange(idx.size)):
                    if used[start] or rng.random() > p:
                        continue
                    length = int(rng.integers(2, m + 1))
                    end = min(start + length, idx.size)
                    if np.any(used[start:end]):
                        continue

                    used[start:end] = True
                    seg_pos = np.arange(start, end)
                    seg_idx = idx[seg_pos]

                    # Shuffle output order
                    perm_pos = seg_pos.copy()
                    rng.shuffle(perm_pos)
                    idx[seg_pos] = idx[perm_pos]

                    # Shuffle timestamp mapping (to keep output ts monotonic)
                    perm_glob = seg_idx.copy()
                    rng.shuffle(perm_glob)
                    for src, dst in zip(seg_idx, perm_glob):
                        ts_perm_map[src] = dst

                    reorder_count += (end - start)

                stats["reorder_packets"] = int(reorder_count)

    return idx, ts_perm_map

def _process_chunk(
    buf, sink, plan, py_rng, stats
):
    n = len(buf)
    if n == 0:
        return 0, 0

    np_rng = np.random.default_rng(py_rng.getrandbits(64))

    # Selection phase
    idx_out, ts_perm_map = _select_indices_and_ts_perm(plan, n, np_rng, stats)

    first = buf[0]
    if isinstance(first, (bytes, bytearray)):
        # Raw records path (fast, no content mod)
        ts_sec, ts_usec, patch_ts = _extract_ts_from_raw_records(buf)

        perm_src = np.arange(n, dtype=np.int64)
        for i, j in ts_perm_map.items():
            perm_src[i] = j
        ts_sec_new = ts_sec[perm_src]
        ts_usec_new = ts_usec[perm_src]

        out_count = 0
        for j in idx_out:
            rec = buf[j]
            rec_patched = patch_ts(rec, int(ts_sec_new[j]), int(ts_usec_new[j]))
            sink.write_raw_record(rec_patched)
            out_count += 1
        return n, out_count

    else:
        # Tuple path (with potential content mods)
        ts_sec = np.fromiter((b[0] for b in buf), dtype=np.int64, count=n)
        ts_usec = np.fromiter((b[1] for b in buf), dtype=np.int64, count=n)

        perm_src = np.arange(n, dtype=np.int64)
        for i, j in ts_perm_map.items():
            perm_src[i] = j
        ts_sec_new = ts_sec[perm_src]
        ts_usec_new = ts_usec[perm_src]

        # Now apply content modifications (seq_offset, length_forge) to selected packets
        out_count = 0
        mod_rng = random.Random(py_rng.getrandbits(64))  # Separate RNG for mods
        for j in idx_out:
            ts_s = int(ts_sec_new[j])
            ts_u = int(ts_usec_new[j])
            pkt_bytes = buf[j][2]

            # Parse to scapy Packet only if needed for this packet
            needs_mod = False
            for step in plan:
                t = str(step.get("type", "")).lower()
                if t in NEED_PARSE_OPS:
                    needs_mod = True
                    break
            if needs_mod:
                pkt = Ether(pkt_bytes)  # Parse
                for step in plan:
                    t = str(step.get("type", "")).lower()
                    p = float(step.get("pct", 0.0))
                    if mod_rng.random() < p:
                        func = PERTURBATIONS.get(t)
                        if func:
                            params = step.get("params", {})
                            modified = func(pkt, **params)
                            if modified is None:  # e.g., loss, but already handled
                                continue
                            elif isinstance(modified, list):  # e.g., retrans
                                for m in modified:
                                    sink.write_raw(ts_s, ts_u, bytes(m))
                                    out_count += 1
                                continue  # Skip original
                            else:
                                pkt = modified
                pkt_bytes = bytes(pkt)  # Back to bytes after mods

            sink.write_raw(ts_s, ts_u, pkt_bytes)
            out_count += 1
        return n, out_count

def _mix_seed(selection_seed: int, in_pcap: str) -> int:
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

    # Choose stream based on plan (fast raw if no parse needed and classic pcap)
    kind = _sniff_kind(in_pcap)
    needs_parse = _plan_needs_parse(perturb_plan)
    if not needs_parse and kind == "pcap":
        stream_func = stream_raw_pcap_records
        log.info(f"Using raw stream for {in_pcap} (no parse needed), with corruption handling")
    else:
        stream_func = stream_pcap_packets
        log.info(f"Using packet stream for {in_pcap} (parse needed)")

    buf: List = []  # Type depends on stream_func

    try:
        for item in stream_func(in_pcap):
            if stream_func is stream_pcap_packets:
                pkt_bytes, ts_sec, ts_usec = item
                buf.append((ts_sec, ts_usec, pkt_bytes))
            else:
                buf.append(item)  # raw bytes
            if len(buf) >= chunk_size:
                _in, _out = _process_chunk(buf, sink, perturb_plan, rng, stats)
                total_in += _in
                total_out += _out
                if show_progress and total_in // progress_every != (total_in - _in) // progress_every:
                    log.info(f"[progress] {in_pcap}  in={total_in} out={total_out}")
                buf.clear()

        if buf:
            _in, _out = _process_chunk(buf, sink, perturb_plan, rng, stats)
            total_in += _in
            total_out += _out
            if show_progress:
                log.info(f"[progress] {in_pcap}  in={total_in} out={total_out}")
    except Exception as e:
        log.error(f"Error processing {in_pcap}: {e}")
        raise
    finally:
        try:
            sink.close()
        except Exception:
            pass

    return {"total_in": total_in, "total_out": total_out, "stats": dict(stats)}