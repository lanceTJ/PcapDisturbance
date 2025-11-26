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
        fmt = "<IIII"
        little = True
    except struct.error:
        ts_sec, ts_usec, incl, orig = struct.unpack(">IIII", first_hdr)
        fmt = ">IIII"
        little = False
    hdr_len = 16

    ts_sec_list = []
    ts_usec_list = []
    for rec in buf:
        s, u, _, _ = struct.unpack(fmt, rec[0:16])  # Extract with len for safety
        ts_sec_list.append(s)
        ts_usec_list.append(u)

    def patch_ts(raw: bytes, new_sec: int, new_usec: int) -> bytes:
        b = bytearray(raw)
        incl = len(raw) - hdr_len
        b[0:16] = struct.pack(fmt, int(new_sec), int(new_usec), incl, incl)
        return bytes(b)

    return (np.array(ts_sec_list, dtype=np.int64),
            np.array(ts_usec_list, dtype=np.int64),
            patch_ts)

def _select_indices_and_ts_perm(
    plan: List[dict], n: int, rng: np.random.Generator, stats: dict
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Modified to return sorted ts_sec_new and ts_usec_new directly, ensuring monotonic increasing ts in output.
    """
    idx = np.arange(n, dtype=np.int64)
    # Placeholder for original ts, will be filled in _process_chunk
    # Return idx_out, ts_sec_perm, ts_usec_perm where perm is sorted for reorder segments

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

                    # Shuffle output order (content disorder)
                    perm_pos = seg_pos.copy()
                    rng.shuffle(perm_pos)
                    idx[seg_pos] = idx[perm_pos]

                    reorder_count += (end - start)

                stats["reorder_packets"] = int(reorder_count)

    return idx

def _process_chunk(
    buf, sink, plan, py_rng, stats
):
    n = len(buf)
    if n == 0:
        return 0, 0

    np_rng = np.random.default_rng(py_rng.getrandbits(64))

    # Selection phase (now only returns idx_out, ts handled below)
    idx_out = _select_indices_and_ts_perm(plan, n, np_rng, stats)

    first = buf[0]
    if isinstance(first, (bytes, bytearray)):
        # Raw records path
        ts_sec, ts_usec, patch_ts = _extract_ts_from_raw_records(buf)

        # To ensure monotonic ts, sort the ts for output positions (after reorder)
        # Collect original ts for idx_out
        orig_ts_sec = ts_sec[idx_out]
        orig_ts_usec = ts_usec[idx_out]
        # Sort them
        sort_indices = np.lexsort((orig_ts_usec, orig_ts_sec))  # Sort by sec then usec
        ts_sec_new = orig_ts_sec[sort_indices]
        ts_usec_new = orig_ts_usec[sort_indices]

        out_count = 0
        for i, j in enumerate(idx_out):
            rec = buf[j]
            rec_patched = patch_ts(rec, int(ts_sec_new[i]), int(ts_usec_new[i]))
            sink.write_raw_record(rec_patched)
            out_count += 1
        return n, out_count

    else:
        # Tuple path
        ts_sec = np.fromiter((b[0] for b in buf), dtype=np.int64, count=n)
        ts_usec = np.fromiter((b[1] for b in buf), dtype=np.int64, count=n)

        # Similar to raw: collect and sort ts for output
        orig_ts_sec = ts_sec[idx_out]
        orig_ts_usec = ts_usec[idx_out]
        sort_indices = np.lexsort((orig_ts_usec, orig_ts_sec))
        ts_sec_new = orig_ts_sec[sort_indices]
        ts_usec_new = orig_ts_usec[sort_indices]

        # Apply content mods...
        out_count = 0
        mod_rng = random.Random(py_rng.getrandbits(64))
        for i, j in enumerate(idx_out):
            ts_s = int(ts_sec_new[i])
            ts_u = int(ts_usec_new[i])
            pkt_bytes = buf[j][2]

            # Calculate needs_mod once per packet (same for all as it's plan-dependent)
            needs_mod = any(str(s.get("type", "")).lower() in NEED_PARSE_OPS for s in plan)
            if needs_mod:
                pkt = Ether(pkt_bytes)
                modified_flag = False  # Track if any modification happened
                for step in plan:
                    t = str(step.get("type", "")).lower()
                    # Skip if not a content-level perturbation (avoid double-applying index-level ones)
                    if t not in NEED_PARSE_OPS:
                        continue
                    p = float(step.get("pct", 0.0))
                    if mod_rng.random() < p:
                        func = PERTURBATIONS.get(t)
                        if func:
                            params = step.get("params", {})
                            modified = func(pkt, **params)
                            if modified is None:
                                modified_flag = True
                                break  # Skip writing this packet entirely
                            elif isinstance(modified, list):
                                for m in modified:
                                    sink.write_raw(ts_s, ts_u, bytes(m))
                                    out_count += 1
                                modified_flag = True
                                break  # Skip original after writing list
                            else:
                                pkt = modified
                                modified_flag = True
                    if t == "seq_offset":
                        new_bytes = bytes(pkt)
                        if len(new_bytes) != len(pkt_bytes):
                            log.warning(f"Seq offset changed packet length from {len(pkt_bytes)} to {len(new_bytes)}, reverting to original")
                            pkt_bytes = pkt_bytes  # Revert to avoid loss
                        else:
                            pkt_bytes = new_bytes
                        out_count += 1
                if not modified_flag or (modified is not None and not isinstance(modified, list)):
                    # Only write if not skipped by None or list
                    pkt_bytes = bytes(pkt)
                    sink.write_raw(ts_s, ts_u, pkt_bytes)
                    out_count += 1
                continue  # Note: this continue is not needed, but if you want to skip something
            else:
                # No mod needed, direct write
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
    
    # Detect source linktype for sink
    kind = _sniff_kind(in_pcap)
    linktype = 1  # Default
    if kind == "pcap":
        with open(in_pcap, "rb") as f:
            header = f.read(24)
            byte_order = 'little' if header[0:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else 'big'
            linktype = int.from_bytes(header[20:24], byte_order)
    
    sink = PcapSinkBuffered(out_pcap, linktype=linktype)
    total_in = total_out = 0
    stats = defaultdict(int)

    needs_parse = _plan_needs_parse(perturb_plan)
    if not needs_parse and kind == "pcap":
        stream_func = stream_raw_pcap_records
        log.info(f"Using raw stream for {in_pcap} (no parse needed), with corruption handling")
    else:
        stream_func = stream_pcap_packets
        log.info(f"Using packet stream for {in_pcap} (parse needed)")

    buf: List = []

    try:
        for item in stream_func(in_pcap):
            if stream_func is stream_pcap_packets:
                pkt_bytes, ts_sec, ts_usec = item
                buf.append((ts_sec, ts_usec, pkt_bytes))
            else:
                buf.append(item)
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