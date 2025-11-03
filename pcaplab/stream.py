# pcaplab/stream.py
from __future__ import annotations
from scapy.all import RawPcapReader, PcapNgReader
from typing import Iterator, Tuple
import struct
import os
from .utils import log  # Import log for warnings

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

def stream_pcap_packets(pcap_path: str) -> Iterator[Tuple[bytes, int, int]]:
    """
    Yield (pkt_bytes, ts_sec, ts_usec) for both pcap and pcapng.
    """
    kind = _sniff_kind(pcap_path)
    if kind == "pcap":
        for pkt_bytes, meta in RawPcapReader(pcap_path):
            yield pkt_bytes, int(meta.sec), int(meta.usec)
    else:  # pcapng
        for pkt in PcapNgReader(pcap_path):
            t = float(getattr(pkt, "time", 0.0))
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1_000_000)
            yield bytes(pkt.original), ts_sec, ts_usec

def stream_raw_pcap_records(pcap_path: str) -> Iterator[bytes]:
    """
    Yield full per-packet records (16-byte header + pkt_bytes) from classic pcap,
    skipping global header. Auto-detects endianness. Only for pcap (not pcapng).
    Handles corrupted files by capping invalid incl_len to snaplen or remaining file size,
    and yielding adjusted records to retain data.
    """
    kind = _sniff_kind(pcap_path)
    if kind != "pcap":
        raise ValueError("Raw record streaming only supports classic pcap (not pcapng)")
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return
        magic = header[0:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            little_endian = True
            fmt_hdr = "<IIII"
            fmt_full = "<IHHIIII"  # For global header if needed
            byte_order = 'little'
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            little_endian = False
            fmt_hdr = ">IIII"
            fmt_full = ">IHHIIII"
            byte_order = 'big'
        else:
            raise ValueError("Invalid pcap magic")
        
        # Parse snaplen from global header (offsets 16-19)
        snaplen = int.from_bytes(header[16:20], byte_order)
        if snaplen == 0:
            snaplen = 262144  # Fallback to Wireshark max if invalid
            log.warning(f"Invalid snaplen 0 in {pcap_path}, using fallback 262144")
        
        file_size = os.fstat(f.fileno()).st_size
        
        while True:
            pos_before_hdr = f.tell()
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt_hdr, hdr)
            
            # Calculate remaining file size
            remaining = file_size - f.tell()
            
            # Repair logic: cap invalid incl_len
            if incl_len > snaplen or incl_len > remaining or incl_len == 0:
                if incl_len == 0:
                    log.warning(f"Skipping zero-length packet at offset {pos_before_hdr} in {pcap_path}")
                    continue  # Skip invalid zero-len
                log.warning(f"Invalid incl_len {incl_len} > snaplen {snaplen} or remaining {remaining} at offset {pos_before_hdr} in {pcap_path}, capping to min({snaplen}, {remaining})")
                incl_len = min(snaplen, remaining)
                orig_len = incl_len  # Assume equal for repair
            
            pkt = f.read(incl_len)
            actual_len = len(pkt)
            
            # If read less than capped (e.g., EOF), adjust
            if actual_len < incl_len:
                log.warning(f"Truncated packet at offset {pos_before_hdr} in {pcap_path}, read {actual_len} < {incl_len}, adjusting header")
                incl_len = actual_len
                orig_len = actual_len
            
            # Repack header with adjusted lengths (keep ts_sec, ts_usec)
            adjusted_hdr = struct.pack(fmt_hdr, ts_sec, ts_usec, incl_len, orig_len)
            
            # Yield only if there's data
            if actual_len > 0:
                yield adjusted_hdr + pkt
            else:
                break  # No more data