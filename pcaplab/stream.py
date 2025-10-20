# pcaplab/stream.py
from scapy.all import RawPcapReader, PcapNgReader, PcapWriter, Ether

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

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
