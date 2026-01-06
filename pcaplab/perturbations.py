# pcaplab/perturbations.py

from __future__ import annotations
import struct
import dpkt

ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_QINQ = 0x88A8

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

def _cksum(data: bytes) -> int:
    return dpkt.in_cksum(data) & 0xFFFF

def _tcp_udp_cksum_ipv4(ip: dpkt.ip.IP, l4_bytes: bytes) -> int:
    # Pseudo header: src(4)+dst(4)+zero(1)+proto(1)+len(2)
    ph = ip.src + ip.dst + struct.pack("!BBH", 0, ip.p, len(l4_bytes))
    return _cksum(ph + l4_bytes)

def _tcp_udp_cksum_ipv6(ip6: dpkt.ip6.IP6, nxt: int, l4_bytes: bytes) -> int:
    # Pseudo header: src(16)+dst(16)+len(4)+zeros(3)+nxt(1)
    ph = ip6.src + ip6.dst + struct.pack("!I", len(l4_bytes)) + b"\x00" * 3 + struct.pack("!B", nxt)
    return _cksum(ph + l4_bytes)

def _unpack_eth_and_vlan(buf: bytes):
    """
    Return: (l2_prefix_bytes, eth_type, l3_bytes_offset)
    l2_prefix_bytes includes Ethernet header + any VLAN tags exactly as in input.
    """
    if len(buf) < 14:
        return None, None, None
    dst = buf[0:6]
    src = buf[6:12]
    etype = struct.unpack("!H", buf[12:14])[0]
    off = 14
    l2 = bytearray(buf[:14])

    # Unwrap one or multiple VLAN tags
    while etype in (ETH_TYPE_VLAN, ETH_TYPE_QINQ):
        if len(buf) < off + 4:
            return None, None, None
        tci = buf[off:off+2]
        etype = struct.unpack("!H", buf[off+2:off+4])[0]
        l2.extend(tci)
        l2.extend(struct.pack("!H", etype))
        off += 4

    return bytes(l2), etype, off

def perturb_length_forge_l3aware(pkt_bytes: bytes, new_len: int, pad_byte: int = 0x00) -> bytes:
    """
    Length-forge that CFM can recognize:
    - Keep Ethernet(+VLAN) header structure
    - Adjust IPv4 total length / IPv6 payload length
    - Adjust UDP length (if UDP)
    - Recompute IPv4 header checksum
    - Recompute TCP/UDP checksum (IPv4/IPv6)
    - Pad/truncate happens INSIDE the IP payload (not after IP end)

    new_len is the final *whole frame* length in bytes (same as your old semantics),
    but we enforce protocol-consistent L3/L4 lengths to match.
    """
    if new_len < 0:
        raise ValueError("new_len must be >= 0")

    l2_prefix, etype, l3_off = _unpack_eth_and_vlan(pkt_bytes)
    if l2_prefix is None:
        # Too short to parse Ethernet; fallback raw
        if len(pkt_bytes) >= new_len:
            return pkt_bytes[:new_len]
        return pkt_bytes + bytes([pad_byte]) * (new_len - len(pkt_bytes))

    # Non-IP: fallback raw (CFM多半不关心，但不破坏)
    if etype not in (ETH_TYPE_IPV4, ETH_TYPE_IPV6):
        if len(pkt_bytes) >= new_len:
            return pkt_bytes[:new_len]
        return pkt_bytes + bytes([pad_byte]) * (new_len - len(pkt_bytes))

    # Ensure we at least keep L2 prefix
    if new_len < len(l2_prefix):
        return l2_prefix[:new_len]

    target_l3_total = new_len - len(l2_prefix)  # bytes after L2 prefix

    if etype == ETH_TYPE_IPV4:
        # Parse IPv4 header
        if len(pkt_bytes) < l3_off + 20:
            return pkt_bytes  # can't parse safely
        vhl = pkt_bytes[l3_off]
        ihl = (vhl & 0x0F) * 4
        if ihl < 20 or len(pkt_bytes) < l3_off + ihl:
            return pkt_bytes

        # Split: ip_hdr_bytes + ip_payload_bytes
        ip_hdr = bytearray(pkt_bytes[l3_off:l3_off+ihl])
        ip_payload = bytearray(pkt_bytes[l3_off+ihl:])

        # We want: ip_total_len == target_l3_total, but must be >= ihl
        ip_total_len = max(ihl, target_l3_total)
        new_payload_len = ip_total_len - ihl

        # Resize payload (pad/truncate inside IP)
        if len(ip_payload) >= new_payload_len:
            ip_payload = ip_payload[:new_payload_len]
        else:
            ip_payload.extend(bytes([pad_byte]) * (new_payload_len - len(ip_payload)))

        # Update IPv4 total length field
        struct.pack_into("!H", ip_hdr, 2, ip_total_len)

        proto = ip_hdr[9]

        # If UDP: update UDP length (header+data)
        if proto == IP_PROTO_UDP and len(ip_payload) >= 8:
            udp = bytearray(ip_payload[:8])
            udp_data = bytes(ip_payload[8:])
            udp_len = 8 + len(udp_data)
            struct.pack_into("!H", udp, 4, udp_len)
            # zero checksum before calc (optional but common)
            struct.pack_into("!H", udp, 6, 0)
            # Build dpkt.ip.IP for checksum pseudo header fields
            ip_tmp = dpkt.ip.IP(bytes(ip_hdr) + bytes(ip_payload))
            c = _tcp_udp_cksum_ipv4(ip_tmp, bytes(udp) + udp_data)
            struct.pack_into("!H", udp, 6, c)
            ip_payload = bytearray(bytes(udp) + udp_data)

        # If TCP: recompute TCP checksum (length = payload len)
        elif proto == IP_PROTO_TCP and len(ip_payload) >= 20:
            # tcp header length is data offset * 4
            off_flags = struct.unpack("!H", ip_payload[12:14])[0]
            doff = ((off_flags >> 12) & 0xF) * 4
            if doff >= 20 and len(ip_payload) >= doff:
                tcp = bytearray(ip_payload[:doff])
                tcp_data = bytes(ip_payload[doff:])
                struct.pack_into("!H", tcp, 16, 0)  # zero checksum
                ip_tmp = dpkt.ip.IP(bytes(ip_hdr) + bytes(ip_payload))
                c = _tcp_udp_cksum_ipv4(ip_tmp, bytes(tcp) + tcp_data)
                struct.pack_into("!H", tcp, 16, c)
                ip_payload = bytearray(bytes(tcp) + tcp_data)

        # Recompute IPv4 header checksum
        struct.pack_into("!H", ip_hdr, 10, 0)
        struct.pack_into("!H", ip_hdr, 10, _cksum(bytes(ip_hdr)))

        out = bytes(l2_prefix) + bytes(ip_hdr) + bytes(ip_payload)

        # Frame-level exact new_len:
        if len(out) >= new_len:
            return out[:new_len]
        return out + bytes([pad_byte]) * (new_len - len(out))

    else:
        # IPv6
        if len(pkt_bytes) < l3_off + 40:
            return pkt_bytes
        ip6_hdr = bytearray(pkt_bytes[l3_off:l3_off+40])
        nxt = ip6_hdr[6]

        ip6_payload = bytearray(pkt_bytes[l3_off+40:])

        # IPv6 payload length field is length after 40-byte header
        # target_l3_total includes ipv6 header too, so payload_len = max(0, target_l3_total-40)
        payload_len = max(0, target_l3_total - 40)

        # Resize payload
        if len(ip6_payload) >= payload_len:
            ip6_payload = ip6_payload[:payload_len]
        else:
            ip6_payload.extend(bytes([pad_byte]) * (payload_len - len(ip6_payload)))

        # Update payload length field
        struct.pack_into("!H", ip6_hdr, 4, payload_len)

        # UDP length and checksum
        if nxt == IP_PROTO_UDP and len(ip6_payload) >= 8:
            udp = bytearray(ip6_payload[:8])
            udp_data = bytes(ip6_payload[8:])
            udp_len = 8 + len(udp_data)
            struct.pack_into("!H", udp, 4, udp_len)
            struct.pack_into("!H", udp, 6, 0)
            ip6_tmp = dpkt.ip6.IP6(bytes(ip6_hdr) + bytes(ip6_payload))
            c = _tcp_udp_cksum_ipv6(ip6_tmp, IP_PROTO_UDP, bytes(udp) + udp_data)
            struct.pack_into("!H", udp, 6, c)
            ip6_payload = bytearray(bytes(udp) + udp_data)

        # TCP checksum
        elif nxt == IP_PROTO_TCP and len(ip6_payload) >= 20:
            off_flags = struct.unpack("!H", ip6_payload[12:14])[0]
            doff = ((off_flags >> 12) & 0xF) * 4
            if doff >= 20 and len(ip6_payload) >= doff:
                tcp = bytearray(ip6_payload[:doff])
                tcp_data = bytes(ip6_payload[doff:])
                struct.pack_into("!H", tcp, 16, 0)
                ip6_tmp = dpkt.ip6.IP6(bytes(ip6_hdr) + bytes(ip6_payload))
                c = _tcp_udp_cksum_ipv6(ip6_tmp, IP_PROTO_TCP, bytes(tcp) + tcp_data)
                struct.pack_into("!H", tcp, 16, c)
                ip6_payload = bytearray(bytes(tcp) + tcp_data)

        out = bytes(l2_prefix) + bytes(ip6_hdr) + bytes(ip6_payload)

        if len(out) >= new_len:
            return out[:new_len]
        return out + bytes([pad_byte]) * (new_len - len(out))
