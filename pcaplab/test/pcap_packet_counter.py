#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

from scapy.utils import RawPcapReader


def is_match_pcap(path: Path) -> bool:
    """Match rule: suffix .pcap OR basename starts with 'cap' (cap*)."""
    name = path.name.lower()
    return name.endswith(".pcap") or name.startswith("cap")


def iter_pcap_files(input_path: Path, recursive: bool = False) -> List[Path]:
    if input_path.is_file():
        return [input_path]

    if not input_path.is_dir():
        raise FileNotFoundError(f"Input path not found: {input_path}")

    if recursive:
        candidates = (p for p in input_path.rglob("*") if p.is_file())
    else:
        candidates = (p for p in input_path.iterdir() if p.is_file())

    pcaps = [p for p in candidates if is_match_pcap(p)]
    pcaps.sort()
    return pcaps


def count_packets_pcap(pcap_path: Path) -> int:
    """Count packets using streaming reader."""
    cnt = 0
    # RawPcapReader supports classic pcap. For other formats (e.g., pcapng),
    # scapy may raise; we handle exceptions and report.
    with RawPcapReader(str(pcap_path)) as reader:
        for _pkt, _meta in reader:
            cnt += 1
    return cnt


def human_rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except Exception:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Count number of packets in each pcap under a file or directory."
    )
    parser.add_argument(
        "input",
        help="Input pcap file or directory containing pcaps.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan directory.",
    )
    parser.add_argument(
        "--csv",
        metavar="OUT.csv",
        help="Optional: write results to CSV (path,count).",
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    base_dir = input_path if input_path.is_dir() else input_path.parent

    try:
        pcaps = iter_pcap_files(input_path, recursive=args.recursive)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2

    if not pcaps:
        print(f"[WARN] No matching pcap files found under: {input_path}", file=sys.stderr)
        return 1

    results: List[Tuple[Path, int]] = []
    total = 0
    ok = 0
    fail = 0

    for p in pcaps:
        try:
            n = count_packets_pcap(p)
            results.append((p, n))
            total += n
            ok += 1
            print(f"{human_rel(p, base_dir)}\t{n}")
        except Exception as e:
            fail += 1
            print(f"{human_rel(p, base_dir)}\tERROR\t{e}", file=sys.stderr)

    print(f"\n[SUMMARY] files_ok={ok} files_fail={fail} total_packets={total}")

    if args.csv:
        out = Path(args.csv).expanduser().resolve()
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                f.write("path,count\n")
                for p, n in results:
                    # quote commas safely
                    f.write(f"\"{str(p)}\",{n}\n")
            print(f"[CSV] wrote: {out}")
        except Exception as e:
            print(f"[ERROR] failed to write CSV: {e}", file=sys.stderr)
            return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
