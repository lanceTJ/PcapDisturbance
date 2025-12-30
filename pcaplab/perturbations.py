# pcaplab/perturbations.py (Refactored to bytes-based, seq_offset uses struct/dpkt checksum)
import struct
import dpkt.ip  # For checksum calc

def perturb_packet_loss(pkt_bytes):
    """Drop packet: return None."""
    return None

def perturb_retransmit(pkt_bytes):
    """Duplicate packet."""
    return [pkt_bytes, pkt_bytes]

def perturb_seq_offset(pkt_bytes, offset=1000):
    """Modify TCP seq number, recalc checksums, preserve length."""
    # Assume Ethernet + IP + TCP (common); skip if not TCP
    if len(pkt_bytes) < 54:  # Min Eth(14)+IP(20)+TCP(20)
        return pkt_bytes
    eth_hdr = pkt_bytes[:14]
    if eth_hdr[12:14] != b'\x08\x00':  # Not IPv4
        return pkt_bytes
    ip_hdr = pkt_bytes[14:34]  # Assume min IP len 20
    ip_len = (ip_hdr[0] & 0x0F) * 4
    if len(pkt_bytes) < 14 + ip_len + 20:  # Min TCP 20
        return pkt_bytes
    proto = ip_hdr[9]
    if proto != 6:  # Not TCP
        return pkt_bytes
    tcp_hdr_start = 14 + ip_len
    tcp_hdr = pkt_bytes[tcp_hdr_start:tcp_hdr_start+20]
    seq = struct.unpack("!I", tcp_hdr[4:8])[0]
    new_seq = seq + int(offset)
    new_tcp_hdr = tcp_hdr[:4] + struct.pack("!I", new_seq) + tcp_hdr[8:]
    
    # Recalc TCP checksum (dpkt way)
    pseudo_hdr = ip_hdr[12:20] + b'\x00\x06' + struct.pack("!H", len(pkt_bytes) - 14 - ip_len)
    tcp_data = pkt_bytes[tcp_hdr_start + 20:]
    checksum = dpkt.in_cksum(pseudo_hdr + new_tcp_hdr + tcp_data)
    new_tcp_hdr = new_tcp_hdr[:16] + struct.pack("!H", checksum) + new_tcp_hdr[18:]
    
    # Recalc IP checksum
    new_ip_hdr = ip_hdr[:10] + b'\x00\x00' + ip_hdr[12:]
    ip_checksum = dpkt.in_cksum(new_ip_hdr)
    new_ip_hdr = new_ip_hdr[:10] + struct.pack("!H", ip_checksum) + new_ip_hdr[12:]
    
    return eth_hdr + new_ip_hdr + new_tcp_hdr + tcp_data

def perturb_length_forge_bytes(pkt_bytes: bytes, new_len: int = None, pad_byte: str = "00") -> bytes:
    """User-provided logic: force packet to new_len (truncate/pad)."""
    if new_len is None:
        new_len = max(1, int(len(pkt_bytes) * 1.5))
    if new_len < 0:
        raise ValueError("new_len must be >= 0")
    # Parse pad_byte from str to byte (like user script)
    if isinstance(pad_byte, str):
        pad_byte = pad_byte.strip().lower()
        if pad_byte.startswith("0x"):
            v = int(pad_byte, 16)
        else:
            try:
                v = int(pad_byte, 10)
            except ValueError:
                v = int(pad_byte, 16)
        if not (0 <= v <= 255):
            raise ValueError("pad_byte must be 0~255")
        pad = bytes([v])
    else:
        pad = bytes([pad_byte])
    if len(pkt_bytes) >= new_len:
        return pkt_bytes[:new_len]
    return pkt_bytes + pad * (new_len - len(pkt_bytes))

def perturb_rate_modify(buffered_pkts, delay_sec=0.05):
    """Placeholder: duplicate to emulate rate change."""
    out = []
    for i, p in enumerate(buffered_pkts):
        out.append(p)
        if i % 4 == 2:
            out.append(buffered_pkts[max(0, i-1)])
    return out

PERTURBATIONS = {
    "loss": perturb_packet_loss,
    "retransmit": perturb_retransmit,
    "seq_offset": perturb_seq_offset,
    "length_forge": perturb_length_forge_bytes,
    "rate_modify": perturb_rate_modify,
}