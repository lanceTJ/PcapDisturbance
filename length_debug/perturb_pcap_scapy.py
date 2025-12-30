#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
完全替代 dpkt 版本的 length forgery 脚本，仅使用 Scapy（无需 dpkt）

用法与原脚本完全一致：

# 10% 概率扰动（单遍，约等于10%）
python perturb_pcap_scapy.py -i in.pcap -o out.pcap -n 10 -l 256 --pad 0x0f --seed 123

# 精确扰动 round(total*10%) 个包（两遍）
python perturb_pcap_scapy.py -i in.pcap -o out.pcap -n 10 -l 256 --pad 0x0f --seed 123 --exact
'''

import argparse
import random
from scapy.all import PcapReader, PcapWriter, Ether, raw, wrpcap
import os

def parse_pad_byte(s: str) -> int:
    """
    Parse pad byte, support:
      --pad 0x0f
      --pad 15
      --pad 0F
    """
    s = s.strip().lower()
    if s.startswith("0x"):
        v = int(s, 16)
    else:
        try:
            v = int(s, 10)
        except ValueError:
            v = int(s, 16)
    if not (0 <= v <= 255):
        raise argparse.ArgumentTypeError("pad 必须是 0~255 的字节值")
    return v


def perturb_packet(buf: bytes, fixed_len: int, pad_byte: int) -> bytes:
    """
    Force entire packet to fixed_len:
    - If longer: truncate
    - If shorter: pad with pad_byte at the end
    No checksum recalculation.
    """
    if fixed_len < 0:
        raise ValueError("fixed_len must be >= 0")
    if len(buf) >= fixed_len:
        return buf[:fixed_len]
    return buf + bytes([pad_byte]) * (fixed_len - len(buf))


def get_linktype_from_file(path: str) -> int:
    """
    Manually read global header to get linktype (compatible with most Scapy versions)
    """
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return 1  # Default Ethernet
        # Detect byte order
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            byte_order = "little"
        elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):  # Nano sec variants
            byte_order = "little" if magic[0] == 0x4d else "big"
        else:
            return 1
        linktype = int.from_bytes(header[20:24], byte_order)
        return linktype


def first_pass_count(path: str) -> int:
    """Count total packets using Scapy PcapReader"""
    count = 0
    with PcapReader(path) as pcap:
        for _ in pcap:
            count += 1
    return count


def main():
    ap = argparse.ArgumentParser(
        description="Randomly perturb n%% packets in a pcap by forcing each selected packet to fixed length (Scapy only)."
    )
    ap.add_argument("-i", "--input", required=True, help="input pcap path")
    ap.add_argument("-o", "--output", required=True, help="output ppcap path")
    ap.add_argument("-n", "--percent", type=float, required=True, help="percentage of packets to perturb (0~100)")
    ap.add_argument("-l", "--length", type=int, required=True, help="fixed packet length in bytes")
    ap.add_argument("--pad", type=parse_pad_byte, default="0x0f", help="pad byte value, e.g. 0x0f (default)")
    ap.add_argument("--seed", type=int, default=None, help="random seed for reproducibility")
    ap.add_argument(
        "--exact",
        action="store_true",
        help="select exactly round(total*n%%) packets (two-pass). Without this flag, uses Bernoulli sampling (one-pass, ~n%%).",
    )
    args = ap.parse_args()

    if not (0.0 <= args.percent <= 100.0):
        raise SystemExit("percent 必须在 0~100 之间")
    if args.length < 0:
        raise SystemExit("length 必须 >= 0")

    random.seed(args.seed)

    # Get linktype manually
    linktype = get_linktype_from_file(args.input)

    if args.exact:
        # Two-pass: exact selection
        total = first_pass_count(args.input)
        k = int(round(total * args.percent / 100.0))
        k = max(0, min(k, total))
        chosen = set(random.sample(range(total), k)) if k > 0 else set()

        packets = []
        with PcapReader(args.input) as reader:
            for idx, pkt in enumerate(reader):
                pkt_bytes = raw(pkt)
                if idx in chosen:
                    pkt_bytes = perturb_packet(pkt_bytes, args.length, args.pad)
                # Rebuild packet to set time correctly
                new_pkt = Ether(pkt_bytes)
                new_pkt.time = pkt.time  # Preserve exact timestamp
                packets.append(new_pkt)

        wrpcap(args.output, packets, linktype=linktype)
        perturbed = k
        print(f"[OK] total={total}, selected={k}, perturbed={perturbed}, out={args.output}")

    else:
        # One-pass: Bernoulli sampling
        packets = []
        total = 0
        perturbed = 0
        p = args.percent / 100.0

        with PcapReader(args.input) as reader:
            for pkt in reader:
                total += 1
                pkt_bytes = raw(pkt)
                if random.random() < p:
                    pkt_bytes = perturb_packet(pkt_bytes, args.length, args.pad)
                    perturbed += 1
                new_pkt = Ether(pkt_bytes)
                new_pkt.time = pkt.time  # Preserve exact timestamp
                packets.append(new_pkt)

        wrpcap(args.output, packets, linktype=linktype)
        print(f"[OK] total={total}, perturbed≈{args.percent:.2f}% -> {perturbed} packets, out={args.output}")


if __name__ == "__main__":
    main()