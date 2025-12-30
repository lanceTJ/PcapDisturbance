#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
pip install dpkt

# 以 10% 概率扰动（单遍，约等于10%）
python perturb_pcap.py -i in.pcap -o out.pcap -n 10 -l 256 --pad 0x0f --seed 123

# 精确扰动 round(total*10%) 个包（两遍）
python perturb_pcap.py -i in.pcap -o out.pcap -n 10 -l 256 --pad 0x0f --seed 123 --exact

'''

import argparse
import random
import dpkt


def parse_pad_byte(s: str) -> int:
    """
    支持:
      --pad 0x0f
      --pad 15
      --pad 0F
    """
    s = s.strip().lower()
    if s.startswith("0x"):
        v = int(s, 16)
    else:
        # 允许直接给十进制或十六进制(无0x)；这里优先按十进制解析
        try:
            v = int(s, 10)
        except ValueError:
            v = int(s, 16)
    if not (0 <= v <= 255):
        raise argparse.ArgumentTypeError("pad 必须是 0~255 的字节值")
    return v


def perturb_packet(buf: bytes, fixed_len: int, pad_byte: int) -> bytes:
    if fixed_len < 0:
        raise ValueError("fixed_len must be >= 0")
    if len(buf) >= fixed_len:
        return buf[:fixed_len]
    return buf + bytes([pad_byte]) * (fixed_len - len(buf))


def first_pass_count(path: str) -> int:
    with open(path, "rb") as f:
        r = dpkt.pcap.Reader(f)
        return sum(1 for _ in r)


def main():
    ap = argparse.ArgumentParser(
        description="Randomly perturb n%% packets in a pcap by forcing each selected packet to fixed length."
    )
    ap.add_argument("-i", "--input", required=True, help="input pcap path")
    ap.add_argument("-o", "--output", required=True, help="output pcap path")
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

    with open(args.input, "rb") as fin:
        reader = dpkt.pcap.Reader(fin)
        linktype = reader.datalink()

        # 输出 writer
        with open(args.output, "wb") as fout:
            writer = dpkt.pcap.Writer(fout, linktype=linktype)

            if args.exact:
                # 两遍：先计数，再精确抽样索引集合
                total = first_pass_count(args.input)
                k = int(round(total * args.percent / 100.0))
                k = max(0, min(k, total))
                chosen = set(random.sample(range(total), k)) if k > 0 else set()

                # 重新打开输入做第二遍
                fin.seek(0)
                reader2 = dpkt.pcap.Reader(fin)

                perturbed = 0
                for idx, (ts, buf) in enumerate(reader2):
                    if idx in chosen:
                        buf2 = perturb_packet(buf, args.length, args.pad)
                        writer.writepkt(buf2, ts=ts)
                        perturbed += 1
                    else:
                        writer.writepkt(buf, ts=ts)

                print(f"[OK] total={total}, selected={k}, perturbed={perturbed}, out={args.output}")

            else:
                # 一遍：每个包以 p 的概率被扰动（期望 n%）
                p = args.percent / 100.0
                total = 0
                perturbed = 0

                for ts, buf in reader:
                    total += 1
                    if random.random() < p:
                        buf2 = perturb_packet(buf, args.length, args.pad)
                        writer.writepkt(buf2, ts=ts)
                        perturbed += 1
                    else:
                        writer.writepkt(buf, ts=ts)

                print(f"[OK] total={total}, perturbed≈{args.percent:.2f}% -> {perturbed} packets, out={args.output}")


if __name__ == "__main__":
    main()
