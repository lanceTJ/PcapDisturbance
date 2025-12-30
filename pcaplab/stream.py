# pcaplab/stream.py (Refactored to use dpkt for packet stream, keep raw for fast path)
from __future__ import annotations
from typing import Iterator
import struct
import os
import dpkt  # Import dpkt for pcap reading
from .utils import log

_PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

def _sniff_kind(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(4)
    if head in _PCAP_MAGIC:
        return "pcap"
    if head == _PCAPNG_MAGIC:
        return "pcapng"
    raise ValueError(f"Unknown capture format (not pcap/pcapng): {path}")

def stream_pcap_packets(pcap_path: str) -> Iterator[Tuple[float, bytes]]:
    """Yield (ts, pkt_bytes) using dpkt (supports pcap only for now)."""
    kind = _sniff_kind(pcap_path)
    if kind != "pcap":
        raise ValueError("dpkt stream supports classic pcap only")
    with open(pcap_path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        for ts, pkt_bytes in reader:
            yield ts, pkt_bytes

def stream_raw_pcap_records(pcap_path: str) -> Iterator[bytes]:
    """Yield full per-packet records (16-byte header + pkt_bytes) from classic pcap."""
    kind = _sniff_kind(pcap_path)
    if kind != "pcap":
        raise ValueError("Raw record streaming only supports classic pcap")
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            log.warning(f"File {pcap_path} too small, no global header")
            return
        magic = header[0:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            fmt_hdr = "<IIII"
            byte_order = 'little'
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            fmt_hdr = ">IIII"
            byte_order = 'big'
        else:
            raise ValueError("Invalid pcap magic")
        
        snaplen = int.from_bytes(header[16:20], byte_order)
        if snaplen == 0 or snaplen > 262144:
            snaplen = 262144
            log.warning(f"Invalid snaplen in {pcap_path}, using 262144")
        
        linktype = int.from_bytes(header[20:24], byte_order)
        log.info(f"Detected linktype {linktype} for {pcap_path}")
        
        file_size = os.fstat(f.fileno()).st_size
        discarded_count = 0
        
        while True:
            pos_before_hdr = f.tell()
            hdr = f.read(16)
            if len(hdr) < 16:
                if discarded_count > 0:
                    log.warning(f"Discarded {discarded_count} invalid records in {pcap_path}")
                break
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt_hdr, hdr)
            except struct.error:
                log.warning(f"Invalid header at {pos_before_hdr} in {pcap_path}, skipping")
                f.seek(pos_before_hdr + 16)
                discarded_count += 1
                continue
            
            remaining = file_size - f.tell()
            if incl_len > snaplen or incl_len > remaining or incl_len <= 0 or incl_len > 1048576:
                log.warning(f"Invalid incl_len {incl_len} at {pos_before_hdr}, capping to min({snaplen}, {remaining})")
                incl_len = min(snaplen, remaining)
                orig_len = incl_len
                if incl_len <= 0:
                    discarded_count += 1
                    continue
            
            pkt = f.read(incl_len)
            actual_len = len(pkt)
            if actual_len < incl_len:
                log.warning(f"Truncated packet at {pos_before_hdr}, adjusting to {actual_len}")
                incl_len = actual_len
                orig_len = actual_len
            
            if actual_len == 0:
                discarded_count += 1
                continue
            
            adjusted_hdr = struct.pack(fmt_hdr, ts_sec, ts_usec, incl_len, orig_len)
            
            yield adjusted_hdr + pkt
    
    if discarded_count > 0:
        log.info(f"Total discarded {discarded_count} invalid records in {pcap_path}")
    return linktype  # Not used now, but kept


def stream_pcap_packets_fast(pcap_path: str) -> Iterator[Tuple[float, bytes]]:
    """
    Fast path: parse classic pcap record headers manually, yield (ts, pkt_bytes).
    Avoid dpkt packet parsing; only uses dpkt for global header validation if you want (optional).
    """
    kind = _sniff_kind(pcap_path)
    if kind != "pcap":
        raise ValueError("fast stream supports classic pcap only")

    with open(pcap_path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return

        magic = gh[0:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            fmt_hdr = "<IIII"
            byte_order = "little"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            fmt_hdr = ">IIII"
            byte_order = "big"
        else:
            raise ValueError("Invalid pcap magic")

        snaplen = int.from_bytes(gh[16:20], byte_order)
        if snaplen <= 0 or snaplen > 262144:
            snaplen = 262144

        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(fmt_hdr, hdr)
            if incl_len <= 0:
                continue
            pkt = f.read(incl_len)
            if len(pkt) != incl_len:
                break
            ts = float(ts_sec) + float(ts_usec) / 1_000_000.0
            yield ts, pkt