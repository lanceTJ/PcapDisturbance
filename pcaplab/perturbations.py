from scapy.layers.inet import IP, TCP, UDP

# --- Core perturbations ---

def perturb_packet_loss(pkt):
    """Drop packet: return None."""
    return None

def perturb_retransmit(pkt):
    """Duplicate packet."""
    cp = pkt.copy()
    return [pkt, cp]

def perturb_seq_offset(pkt, offset=1000):
    """TCP sequence number offset. Recompute checksums by deleting them."""
    if TCP in pkt:
        p2 = pkt.copy()
        p2[TCP].seq = int(p2[TCP].seq) + int(offset)
        if IP in p2:
            if hasattr(p2[IP], "chksum"): del p2[IP].chksum
            if hasattr(p2[IP], "len"):    del p2[IP].len
        if hasattr(p2[TCP], "chksum"):    del p2[TCP].chksum
        return p2
    return pkt

def perturb_length_forgery(pkt, new_len=None, pad_byte=b"\x00"):
    """Modify Raw payload length; if none, 1.5x."""
    p2 = pkt.copy()
    raw_layer = p2.getlayer("Raw")
    if raw_layer is not None:
        data = bytes(raw_layer.load)
        target = int(new_len) if new_len else max(1, int(len(data) * 1.5))
        if len(data) >= target:
            raw_layer.load = data[:target]
        else:
            raw_layer.load = data + pad_byte * (target - len(data))
    else:
        # inject dummy payload when none
        raw_layer = pad_byte * (new_len or 32)
        p2 = p2 / raw_layer
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
