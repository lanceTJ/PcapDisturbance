# pcaplab/stream.py
from scapy.all import RawPcapReader, PcapNgReader, PcapWriter, Ether

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

class PcapSinkBuffered:
    def __init__(self, out_path: str, linktype: int = 1, buf_bytes: int = 8 * 1024 * 1024):
        # 自己维护缓冲区，减少 write 次数
        self._f = open(out_path, "wb", buffering=0)
        # pcap 全局头（pcap，不是 pcapng）
        self._f.write(b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00" + b"\x00\x00\x00\x00" +
                      b"\x00\x00\x00\x00" + b"\xff\xff\x00\x00" + linktype.to_bytes(4, "little"))
        self._buf = bytearray()
        self._limit = buf_bytes

    def write_raw(self, ts_sec: int, ts_usec: int, pkt_bytes: bytes):
        caplen = incllen = len(pkt_bytes)
        hdr = (ts_sec.to_bytes(4,"little") + ts_usec.to_bytes(4,"little") +
               incllen.to_bytes(4,"little") + caplen.to_bytes(4,"little"))
        self._buf += hdr
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


def sniff_pcap_kind(path: str) -> str | None:
    """Return 'pcap', 'pcapng', or None by magic bytes (extension-agnostic)."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head in PCAP_MAGIC:
        return "pcap"
    if head == PCAPNG_MAGIC:
        return "pcapng"
    return None

def stream_pcap_packets(pcap_path: str):
    """Yield raw bytes from either pcap or pcapng (extensionless safe)."""
    kind = sniff_pcap_kind(pcap_path)
    if kind == "pcapng":
        for pkt in PcapNgReader(pcap_path):
            yield bytes(pkt.original)
    elif kind == "pcap":
        for pkt_data, _ in RawPcapReader(pcap_path):
            yield pkt_data
    else:
        raise ValueError(f"Not a pcap/pcapng file (by magic): {pcap_path}")

def parse_packet(pkt_bytes: bytes):
    return Ether(pkt_bytes)

class PcapSink:
    def __init__(self, out_path: str, append=False):
        self._writer = PcapWriter(out_path, append=append, sync=True)  # outputs PCAP format
    def write(self, pkt): self._writer.write(pkt)
    def close(self): self._writer.close()
