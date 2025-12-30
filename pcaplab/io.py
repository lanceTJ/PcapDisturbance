# pcaplab/io.py (Refactored to use dpkt.pcap.Writer for buffered write)
from __future__ import annotations
import dpkt  # Import dpkt for Writer

class PcapSinkBuffered:
    """Buffered PCAP writer using dpkt (little-endian by default)."""
    def __init__(self, out_path: str, linktype: int = 1, buf_size: int = 100):
        self._writer = dpkt.pcap.Writer(open(out_path, "wb"), linktype=linktype)
        self._buf = []
        self._limit = buf_size  # Buffer N packets before flush

    def writepkt(self, pkt_bytes: bytes, ts: float):
        self._buf.append((ts, pkt_bytes))
        if len(self._buf) >= self._limit:
            self.flush()

    def flush(self):
        for ts, b in self._buf:
            self._writer.writepkt(b, ts=ts)
        self._buf.clear()

    def close(self):
        self.flush()
        self._writer.close()