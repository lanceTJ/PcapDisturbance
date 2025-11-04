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
    and yielding adjusted records to retain data. Enhanced to skip invalid records and log more.
    """
    kind = _sniff_kind(pcap_path)
    if kind != "pcap":
        raise ValueError("Raw record streaming only supports classic pcap (not pcapng)")
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            log.warning(f"File {pcap_path} too small, no global header")
            return
        magic = header[0:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            little_endian = True
            fmt_hdr = "<IIII"
            byte_order = 'little'
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            little_endian = False
            fmt_hdr = ">IIII"
            byte_order = 'big'
        else:
            raise ValueError("Invalid pcap magic")
        
        # Parse snaplen from global header (offsets 16-19)
        snaplen = int.from_bytes(header[16:20], byte_order)
        if snaplen == 0 or snaplen > 262144:
            snaplen = 262144  # Fallback to max if invalid
            log.warning(f"Invalid snaplen in {pcap_path}, using fallback 262144")
        
        # Parse linktype (offsets 20-23)
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
                log.warning(f"Invalid header at offset {pos_before_hdr} in {pcap_path}, skipping 16 bytes")
                f.seek(pos_before_hdr + 16)  # Skip invalid hdr
                discarded_count += 1
                continue
            
            remaining = file_size - f.tell()
            
            # Repair logic: cap invalid incl_len
            if incl_len > snaplen or incl_len > remaining or incl_len <= 0 or incl_len > 1048576:  # Extra check for absurdly large
                log.warning(f"Invalid incl_len {incl_len} at offset {pos_before_hdr} in {pcap_path}, capping to min({snaplen}, {remaining})")
                incl_len = min(snaplen, remaining)
                orig_len = incl_len
                if incl_len <= 0:
                    discarded_count += 1
                    continue
            
            pkt = f.read(incl_len)
            actual_len = len(pkt)
            
            # If truncated, adjust
            if actual_len < incl_len:
                log.warning(f"Truncated packet at offset {pos_before_hdr} in {pcap_path}, read {actual_len} < {incl_len}, adjusting header")
                incl_len = actual_len
                orig_len = actual_len
            
            # Skip if no data
            if actual_len == 0:
                discarded_count += 1
                continue
            
            # Repack header
            adjusted_hdr = struct.pack(fmt_hdr, ts_sec, ts_usec, incl_len, orig_len)
            
            yield adjusted_hdr + pkt
    
    if discarded_count > 0:
        log.info(f"Total discarded {discarded_count} invalid records in {pcap_path}, but retained rest")
    return linktype  # Return linktype for sink to use