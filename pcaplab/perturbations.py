# pcaplab/perturbations.py
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import Raw  # Import Raw for payload injection

# --- Core perturbations ---

def perturb_packet_loss(pkt):
    """Drop packet: return None."""
    return None

def perturb_retransmit(pkt):
    """Duplicate packet."""
    cp = pkt.copy()
    return [pkt, cp]

def perturb_seq_offset(pkt, offset=1000):
    """TCP sequence number offset. Recompute only checksums, preserve length to avoid payload loss."""
    if TCP in pkt:
        p2 = pkt.copy()
        p2[TCP].seq = int(p2[TCP].seq) + int(offset)
        if IP in p2:
            del p2[IP].chksum  # Force IP checksum recalc
        del p2[TCP].chksum  # Force TCP checksum recalc
        # Explicitly set len to original to prevent scapy bugs
        if IP in p2:
            p2[IP].len = len(bytes(p2[IP]))  # Recalc len manually after changes
        return p2
    return pkt

def perturb_length_forgery(pkt, new_len=None, pad_byte=b"\x00"):
    """Modify Raw payload length; if none, 1.5x. Convert pad_byte to bytes if str."""
    # Convert pad_byte to bytes if it's a hex string
    if isinstance(pad_byte, str):
        try:
            pad_byte = bytes.fromhex(pad_byte)
            if len(pad_byte) != 1:
                raise ValueError("pad_byte must be a single byte")
        except ValueError:
            pad_byte = b"\x00"  # Fallback to default if invalid

    p2 = pkt.copy()
    raw_layer = p2.getlayer("Raw")
    if raw_layer is not None:
        data = bytes(raw_layer.load)
        target = int(new_len) if new_len else max(1, int(len(data) * 1.5))
        if len(data) >= target:
            raw_layer.load = data[:target]
        else:
            raw_layer.load = data + (pad_byte * (target - len(data)))
    else:
        # inject dummy payload when none
        dummy_payload = pad_byte * (new_len or 32)
        p2 = p2 / Raw(load=dummy_payload)  # Use Raw to ensure bytes
    if IP in p2:
        if hasattr(p2[IP], "chksum"): del p2[IP].chksum
        if hasattr(p2[IP], "len"):    del p2[IP].len
    if TCP in p2 and hasattr(p2[TCP], "chksum"): del p2[TCP].chksum
    if UDP in p2 and hasattr(p2[UDP], "chksum"): del p2[UDP].chksum
    return p2

def perturb_rate_modify(buffered_pkts, delay_sec=0.05):
    """
    Offline pcap has no realtime clock; this is a placeholder to change local ordering/density.
    Strategy: duplicate neighbors periodically to emulate jitter/gap.
    """
    out = []
    for i, p in enumerate(buffered_pkts):
        out.append(p)
        if i % 4 == 2:
            out.append(buffered_pkts[max(0, i-1)].copy())
    return out

PERTURBATIONS = {
    "loss": perturb_packet_loss,
    "retransmit": perturb_retransmit,
    "seq_offset": perturb_seq_offset,
    "length_forge": perturb_length_forgery,
    "rate_modify": perturb_rate_modify,  # works on buffered sequences (used rarely)
}