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
    """
    Process a chunk of packets, applying perturbations and writing to sink.
    Fixed timestamp handling to preserve relative intervals without global sorting.
    Refactored content modification loop to avoid duplicates and incorrect skips.
    """
    n = len(buf)
    if n == 0:
        return 0, 0

    np_rng = np.random.default_rng(py_rng.getrandbits(64))

    # Selection phase: get perturbed indices
    idx_out = _select_indices_and_ts_perm(plan, n, np_rng, stats)

    # Determine if we need parsing for content mods
    needs_mod = _plan_needs_parse(plan)

    first = buf[0]
    is_raw = isinstance(first, (bytes, bytearray))

    # Extract timestamps
    if is_raw:
        ts_sec, ts_usec, patch_ts = _extract_ts_from_raw_records(buf)
    else:
        ts_sec = np.fromiter((b[0] for b in buf), dtype=np.int64, count=n)
        ts_usec = np.fromiter((b[1] for b in buf), dtype=np.int64, count=n)

    # Get original ts for selected indices
    orig_ts_sec = ts_sec[idx_out]
    orig_ts_usec = ts_usec[idx_out]

    # Fix: Compute new ts by shifting relative to the first selected packet's ts
    # This preserves relative deltas, ensures monotonicity in output order
    if len(idx_out) > 0:
        base_sec = orig_ts_sec[0]
        base_usec = orig_ts_usec[0]
        # Compute deltas and apply cumulatively to ensure increasing order
        prev_sec, prev_usec = base_sec, base_usec
        ts_sec_new = np.zeros_like(orig_ts_sec)
        ts_usec_new = np.zeros_like(orig_ts_usec)
        ts_sec_new[0] = base_sec
        ts_usec_new[0] = base_usec
        for i in range(1, len(idx_out)):
            delta_sec = orig_ts_sec[i] - orig_ts_sec[i-1]
            delta_usec = orig_ts_usec[i] - orig_ts_usec[i-1]
            new_sec = prev_sec + delta_sec
            new_usec = prev_usec + delta_usec
            if new_usec < 0:
                new_usec += 1_000_000
                new_sec -= 1
            elif new_usec >= 1_000_000:
                new_sec += new_usec // 1_000_000
                new_usec %= 1_000_000
            # Ensure non-decreasing (add epsilon if needed)
            if new_sec < prev_sec or (new_sec == prev_sec and new_usec <= prev_usec):
                new_sec = prev_sec
                new_usec = prev_usec + 1  # Minimal increment
            ts_sec_new[i] = new_sec
            ts_usec_new[i] = new_usec
            prev_sec, prev_usec = new_sec, new_usec
    else:
        return n, 0  # No outputs

    out_count = 0
    mod_rng = random.Random(py_rng.getrandbits(64))

    for i, j in enumerate(idx_out):
        ts_s = int(ts_sec_new[i])
        ts_u = int(ts_usec_new[i])

        if is_raw:
            rec = buf[j]
            if needs_mod:
                # For raw, if mod needed, parse temporarily (performance hit, but correct)
                try:
                    pkt = Ether(rec[16:])  # Skip pcap header
                    pkt_bytes = bytes(pkt)
                except Exception as e:
                    log.warning(f"Failed to parse raw record for mod: {e}, skipping mod")
                    pkt_bytes = rec[16:]
            else:
                # No mod, direct patch and write
                rec_patched = patch_ts(rec, ts_s, ts_u)
                sink.write_raw_record(rec_patched)
                out_count += 1
                continue
        else:
            pkt_bytes = buf[j][2]

        if needs_mod:
            try:
                pkt = Ether(pkt_bytes)
            except Exception as e:
                log.warning(f"Packet parse failed: {e}, skipping mod")
                sink.write_raw(ts_s, ts_u, pkt_bytes)
                out_count += 1
                continue

            skip_packet = False
            output_list = None
            for step in plan:
                t = str(step.get("type", "")).lower()
                if t not in NEED_PARSE_OPS:
                    continue
                p = float(step.get("pct", 0.0))
                if mod_rng.random() < p:
                    func = PERTURBATIONS.get(t)
                    if func:
                        params = step.get("params", {})
                        modified = func(pkt, **params)
                        if modified is None:
                            skip_packet = True
                            break
                        elif isinstance(modified, list):
                            output_list = modified
                            break
                        else:
                            pkt = modified

            if skip_packet:
                continue  # None: drop this packet

            if output_list:
                for m in output_list:
                    sink.write_raw(ts_s, ts_u, bytes(m))
                    out_count += 1
                continue  # Wrote list, skip original

            # Final check for seq_offset or other (outside loop)
            pkt_bytes = bytes(pkt)
            orig_len = len(buf[j][2]) if not is_raw else len(rec) - 16
            if len(pkt_bytes) != orig_len:
                log.warning(f"Modification changed length from {orig_len} to {len(pkt_bytes)}, reverting")
                pkt_bytes = buf[j][2] if not is_raw else rec[16:]

        # Write the (possibly modified) packet
        if is_raw:
            rec_patched = patch_ts(b'\x00'*16 + pkt_bytes, ts_s, ts_u)  # Dummy header, patch will fix
            sink.write_raw_record(rec_patched)
        else:
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