# pcaplab/stream.py
from __future__ import annotations
from scapy.all import RawPcapReader, PcapNgReader
from typing import Iterator, Tuple

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
            # meta.sec, meta.usec are integers
            yield pkt_bytes, int(meta.sec), int(meta.usec)
    else:  # pcapng
        # PcapNgReader yields scapy Packets with .time (float seconds)
        for pkt in PcapNgReader(pcap_path):
            t = float(getattr(pkt, "time", 0.0))
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1_000_000)
            yield bytes(pkt.original), ts_sec, ts_usec
