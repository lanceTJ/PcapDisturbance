# pcaplab/io.py
from __future__ import annotations

class PcapSinkBuffered:
    """
    Fast buffered PCAP writer (classic pcap, little-endian).
    write_raw(ts_sec, ts_usec, pkt_bytes) appends a packet without parsing.
    """
    def __init__(self, out_path: str, linktype: int = 1, buf_bytes: int = 8 * 1024 * 1024):
        # linktype=1 => LINKTYPE_ETHERNET; adjust if needed
        self._f = open(out_path, "wb", buffering=0)
        # global header (little-endian magic d4 c3 b2 a1)
        self._f.write(
            b"\xd4\xc3\xb2\xa1" +          # magic
            b"\x02\x00" + b"\x04\x00" +    # version 2.4
            b"\x00\x00\x00\x00" +          # thiszone
            b"\x00\x00\x00\x00" +          # sigfigs
            b"\xff\xff\x00\x00" +          # snaplen (65535)
            linktype.to_bytes(4, "little") # network
        )
        self._buf = bytearray()
        self._limit = int(buf_bytes)

    def write_raw(self, ts_sec: int, ts_usec: int, pkt_bytes: bytes):
        incl = cap = len(pkt_bytes)
        # per-packet header
        self._buf += (
            int(ts_sec).to_bytes(4, "little") +
            int(ts_usec).to_bytes(4, "little") +
            int(incl).to_bytes(4, "little") +
            int(cap).to_bytes(4, "little")
        )
        self._buf += pkt_bytes
        if len(self._buf) >= self._limit:
            self._f.write(self._buf)
            self._buf.clear()

    def flush(self):
        if self._buf:
            self._f.write(self._buf)
            self._buf.clear()

    def close(self):
        self.flush()
        self._f.close()
