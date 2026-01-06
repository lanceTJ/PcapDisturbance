#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pcap_len_cmp_by_label.py

Compare packet-length statistics BEFORE vs AFTER a perturbation under the same YAML labeling rules.

What this tool does
- Reads two PCAP/PCAPNG files: a "before" pcap and an "after" pcap
- Applies YAML rules to label packets (priority-ordered first match)
- Computes descriptive statistics of packet size (overall + per-label) for matched packets
- Produces side-by-side comparisons and effect metrics:
  * Delta/ratio of core stats (mean/var/std/quantiles)
  * Effect size: Cohen's d
  * Distribution distances:
      - KS statistic (two-sample, exact over the observed values)
      - JS divergence over a common histogram grid
  * Distribution "fingerprint": top-K most frequent lengths and their shares

Typical usage
  python3 pcap_len_cmp_by_label.py before.pcap after.pcap --yaml rules.yaml --metric caplen

Optional visualization (PNG)
  python3 pcap_len_cmp_by_label.py before.pcap after.pcap --plot-dir ./plots --top-labels 5

Notes
- metric=caplen uses raw record length (len(pcap record)).
- metric=iplen uses IP total length (IPv4: ip.len, IPv6: ip.plen + 40).
- This script performs two passes per pcap:
  pass1: builds minimal directional flow state used by YAML fields
  pass2: labels packets and collects lengths
"""

import argparse
import datetime as dt
import json
import math
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import dpkt
import numpy as np
import yaml


DEFAULT_YAML = "/mnt/raid/luohaoran/cicids2018/SaP/pcapphaser/label_rules/cic2018_improved_rules_simplifed.yaml"


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# -------------------------
# Time parsing / packet parse
# -------------------------

def parse_iso_to_epoch(s: str, tz_offset_hours: float = 0.0) -> float:
    """
    YAML time strings are typically naive ISO8601 (no timezone).
    We interpret them as UTC+tz_offset_hours, then convert to UTC epoch seconds.
    """
    try:
        t = dt.datetime.fromisoformat(s)
    except ValueError:
        if s.endswith("Z"):
            t = dt.datetime.fromisoformat(s[:-1])
        else:
            raise
    t_utc = t - dt.timedelta(hours=tz_offset_hours)
    return t_utc.replace(tzinfo=dt.timezone.utc).timestamp()


def ip_to_str(ip_bytes: bytes) -> str:
    if len(ip_bytes) == 4:
        return ".".join(str(b) for b in ip_bytes)
    if len(ip_bytes) == 16:
        import ipaddress
        return str(ipaddress.IPv6Address(ip_bytes))
    return ""


def get_packet_fields(ts: float, buf: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse L2->L3->L4 and return the basic fields used by the rule engine.
    Returns None for non-IP packets or parse errors.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
    except Exception:
        return None

    fields: Dict[str, Any] = {
        "ts": ts,
        "src_ip": None,
        "dst_ip": None,
        "proto": None,
        "src_port": None,
        "dst_port": None,
        "tcp_rst": 0,
        "tcp_payload_len": 0,
        "caplen": len(buf),
        "iplen": None,
    }

    # IPv4 / IPv6
    if isinstance(ip, dpkt.ip.IP):
        fields["proto"] = ip.p
        fields["src_ip"] = ip_to_str(ip.src)
        fields["dst_ip"] = ip_to_str(ip.dst)
        fields["iplen"] = int(ip.len)
        l4 = ip.data
    elif isinstance(ip, dpkt.ip6.IP6):
        fields["proto"] = ip.nxt
        fields["src_ip"] = ip_to_str(ip.src)
        fields["dst_ip"] = ip_to_str(ip.dst)
        fields["iplen"] = int(ip.plen) + 40  # IPv6 payload + fixed header
        l4 = ip.data
    else:
        return None

    # TCP / UDP
    if isinstance(l4, dpkt.tcp.TCP):
        fields["src_port"] = int(l4.sport)
        fields["dst_port"] = int(l4.dport)
        flags = int(l4.flags)
        fields["tcp_rst"] = 1 if (flags & dpkt.tcp.TH_RST) else 0
        fields["tcp_payload_len"] = len(l4.data) if l4.data else 0
    elif isinstance(l4, dpkt.udp.UDP):
        fields["src_port"] = int(l4.sport)
        fields["dst_port"] = int(l4.dport)

    return fields


# -------------------------
# Rule compilation / eval
# -------------------------

@dataclass
class TimeWindow:
    ranges: List[Tuple[float, float]]


@dataclass
class Rule:
    label: str
    priority: int
    terms: List[Dict[str, Any]]
    time_window: Optional[TimeWindow] = None

    src_ip_set: Optional[set] = None
    dst_ip_set: Optional[set] = None
    any_ip_set: Optional[set] = None

    dst_ip_eq: Optional[str] = None
    src_ip_eq: Optional[str] = None

    src_port_terms: List[Tuple[str, Any]] = None
    dst_port_terms: List[Tuple[str, Any]] = None

    zero_fwd_term: Optional[Tuple[str, bool]] = None
    total_fwd_len_term: Optional[Tuple[str, int]] = None
    bwd_rst_flags_term: Optional[Tuple[str, int]] = None

    def __post_init__(self):
        self.src_port_terms = []
        self.dst_port_terms = []


def compile_rules(yaml_path: str, tz_offset_hours: float) -> List[Rule]:
    with open(yaml_path, "r", encoding="utf-8") as f:
        y = yaml.safe_load(f)

    rules_raw = y.get("rules", [])
    compiled: List[Rule] = []

    for r in rules_raw:
        label = r.get("label", "UNKNOWN")
        priority = int(r.get("priority", 0))
        terms = r.get("match", []) or []

        rule = Rule(label=label, priority=priority, terms=terms)

        for t in terms:
            field = t.get("field")
            op = t.get("op")
            val = t.get("value")

            if field == "time_window":
                if op == "range":
                    start, end = val
                    tw = [(parse_iso_to_epoch(start, tz_offset_hours),
                           parse_iso_to_epoch(end, tz_offset_hours))]
                elif op == "ranges":
                    tw = []
                    for start, end in val:
                        tw.append((parse_iso_to_epoch(start, tz_offset_hours),
                                   parse_iso_to_epoch(end, tz_offset_hours)))
                else:
                    raise ValueError(f"Unsupported time_window op: {op}")
                rule.time_window = TimeWindow(ranges=tw)

            elif field in ("src_ip", "dst_ip", "any_ip"):
                if op == "in":
                    s = set(val)
                    if field == "src_ip":
                        rule.src_ip_set = (rule.src_ip_set or set()) | s
                    elif field == "dst_ip":
                        rule.dst_ip_set = (rule.dst_ip_set or set()) | s
                    else:
                        rule.any_ip_set = (rule.any_ip_set or set()) | s
                elif op == "==":
                    if field == "src_ip":
                        rule.src_ip_eq = str(val)
                    elif field == "dst_ip":
                        rule.dst_ip_eq = str(val)
                    else:
                        rule.any_ip_set = (rule.any_ip_set or set()) | {str(val)}

            elif field == "src_port":
                rule.src_port_terms.append((op, val))
            elif field == "dst_port":
                rule.dst_port_terms.append((op, val))

            elif field == "zero_fwd":
                rule.zero_fwd_term = (op, bool(val))
            elif field == "total_fwd_len":
                rule.total_fwd_len_term = (op, int(val))
            elif field == "bwd_rst_flags":
                rule.bwd_rst_flags_term = (op, int(val))

        compiled.append(rule)

    compiled.sort(key=lambda x: x.priority, reverse=True)
    return compiled


def cmp(op: str, a: Any, b: Any) -> bool:
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == "in":
        return a in b
    raise ValueError(f"Unsupported op: {op}")


def in_time_window(ts: float, tw: Optional[TimeWindow]) -> bool:
    if tw is None:
        return True
    for start, end in tw.ranges:
        if start <= ts <= end:
            return True
    return False


def make_flow_key(fields: Dict[str, Any]) -> Optional[Tuple[str, int, str, int, int]]:
    if fields["src_ip"] is None or fields["dst_ip"] is None:
        return None
    if fields["src_port"] is None or fields["dst_port"] is None:
        return None
    if fields["proto"] is None:
        return None
    return (fields["src_ip"], int(fields["src_port"]), fields["dst_ip"], int(fields["dst_port"]), int(fields["proto"]))


def reverse_flow_key(k: Tuple[str, int, str, int, int]) -> Tuple[str, int, str, int, int]:
    return (k[2], k[3], k[0], k[1], k[4])


def eval_rule(
    rule: Rule,
    fields: Dict[str, Any],
    payload_bytes_dir: Dict[Tuple[str, int, str, int, int], int],
    rst_pkts_dir: Dict[Tuple[str, int, str, int, int], int],
) -> bool:
    if not in_time_window(fields["ts"], rule.time_window):
        return False

    src_ip = fields["src_ip"]
    dst_ip = fields["dst_ip"]
    if src_ip is None or dst_ip is None:
        return False

    if rule.src_ip_eq is not None and src_ip != rule.src_ip_eq:
        return False
    if rule.dst_ip_eq is not None and dst_ip != rule.dst_ip_eq:
        return False
    if rule.src_ip_set is not None and src_ip not in rule.src_ip_set:
        return False
    if rule.dst_ip_set is not None and dst_ip not in rule.dst_ip_set:
        return False
    if rule.any_ip_set is not None and (src_ip not in rule.any_ip_set and dst_ip not in rule.any_ip_set):
        return False

    if rule.src_port_terms:
        sp = fields["src_port"]
        if sp is None:
            return False
        for op, val in rule.src_port_terms:
            if not cmp(op, int(sp), int(val)):
                return False

    if rule.dst_port_terms:
        dp = fields["dst_port"]
        if dp is None:
            return False
        for op, val in rule.dst_port_terms:
            if not cmp(op, int(dp), int(val)):
                return False

    fk = make_flow_key(fields)
    if (rule.zero_fwd_term or rule.total_fwd_len_term or rule.bwd_rst_flags_term) and fk is None:
        return False

    if rule.zero_fwd_term is not None:
        op, want = rule.zero_fwd_term
        fwd_bytes = int(payload_bytes_dir.get(fk, 0))
        got = (fwd_bytes == 0)
        if not cmp(op, got, want):
            return False

    if rule.total_fwd_len_term is not None:
        op, v = rule.total_fwd_len_term
        fwd_bytes = int(payload_bytes_dir.get(fk, 0))
        if not cmp(op, fwd_bytes, int(v)):
            return False

    if rule.bwd_rst_flags_term is not None:
        op, v = rule.bwd_rst_flags_term
        rk = reverse_flow_key(fk)
        bwd_rst = int(rst_pkts_dir.get(rk, 0))
        if not cmp(op, bwd_rst, int(v)):
            return False

    return True


# -------------------------
# Stats and distances
# -------------------------

def compute_stats(arr: np.ndarray) -> Dict[str, Any]:
    if arr.size == 0:
        return {"count": 0}

    x = arr.astype(np.float64)
    n = int(x.size)

    mean = float(x.mean())
    var = float(x.var(ddof=1)) if n > 1 else 0.0
    std = float(math.sqrt(var))
    mn = float(x.min())
    mx = float(x.max())
    med = float(np.median(x))
    q1 = float(np.quantile(x, 0.25))
    q3 = float(np.quantile(x, 0.75))
    iqr = float(q3 - q1)
    p90 = float(np.quantile(x, 0.90))
    p95 = float(np.quantile(x, 0.95))
    p99 = float(np.quantile(x, 0.99))

    mad = float(np.median(np.abs(x - med)))
    cv = float(std / mean) if mean != 0 else float("inf")

    if n >= 3 and std > 0:
        m3 = float(np.mean((x - mean) ** 3))
        skew = float(m3 / (std ** 3))
    else:
        skew = 0.0

    if n >= 4 and std > 0:
        m4 = float(np.mean((x - mean) ** 4))
        kurt_excess = float(m4 / (std ** 4) - 3.0)
    else:
        kurt_excess = 0.0

    return {
        "count": n,
        "mean": mean,
        "var": var,
        "std": std,
        "min": mn,
        "q1": q1,
        "median": med,
        "q3": q3,
        "iqr": iqr,
        "p90": p90,
        "p95": p95,
        "p99": p99,
        "max": mx,
        "mad": mad,
        "cv": cv,
        "skew": skew,
        "kurtosis_excess": kurt_excess,
    }


def top_k_freq(arr: np.ndarray, k: int = 10) -> List[Tuple[int, int, float]]:
    """
    Return [(value, count, ratio), ...] for top-k most frequent values.
    """
    if arr.size == 0:
        return []
    vals, cnts = np.unique(arr.astype(np.int64), return_counts=True)
    idx = np.argsort(cnts)[::-1][:k]
    total = int(arr.size)
    out = []
    for i in idx:
        out.append((int(vals[i]), int(cnts[i]), float(cnts[i] / total)))
    return out


def cohen_d(a: np.ndarray, b: np.ndarray) -> float:
    """
    Cohen's d using pooled standard deviation.
    """
    if a.size < 2 or b.size < 2:
        return 0.0
    a = a.astype(np.float64)
    b = b.astype(np.float64)
    na, nb = a.size, b.size
    va = a.var(ddof=1)
    vb = b.var(ddof=1)
    sp = math.sqrt(((na - 1) * va + (nb - 1) * vb) / (na + nb - 2)) if (na + nb - 2) > 0 else 0.0
    if sp == 0:
        return 0.0
    return float((b.mean() - a.mean()) / sp)


def ks_statistic(a: np.ndarray, b: np.ndarray) -> float:
    """
    Two-sample KS statistic without SciPy.
    """
    if a.size == 0 or b.size == 0:
        return 0.0
    a = np.sort(a.astype(np.float64))
    b = np.sort(b.astype(np.float64))
    na, nb = a.size, b.size

    allv = np.sort(np.unique(np.concatenate([a, b])))
    # Use searchsorted to compute CDF at each unique value.
    cdfa = np.searchsorted(a, allv, side="right") / na
    cdfb = np.searchsorted(b, allv, side="right") / nb
    return float(np.max(np.abs(cdfa - cdfb)))


def js_divergence_hist(a: np.ndarray, b: np.ndarray, bins: np.ndarray) -> float:
    """
    Jensen-Shannon divergence on histogram distributions over shared bins.
    Returns value in [0, ln(2)] (natural log).
    """
    if a.size == 0 or b.size == 0:
        return 0.0
    ha, _ = np.histogram(a, bins=bins)
    hb, _ = np.histogram(b, bins=bins)
    pa = ha.astype(np.float64)
    pb = hb.astype(np.float64)
    pa = pa / (pa.sum() + 1e-12)
    pb = pb / (pb.sum() + 1e-12)
    m = 0.5 * (pa + pb)

    def kl(p, q):
        mask = p > 0
        return float(np.sum(p[mask] * np.log((p[mask] + 1e-12) / (q[mask] + 1e-12))))

    return 0.5 * kl(pa, m) + 0.5 * kl(pb, m)


def l1_distance_hist(a: np.ndarray, b: np.ndarray, bins: np.ndarray) -> float:
    """
    L1 distance between normalized histograms in [0, 2].
    """
    if a.size == 0 or b.size == 0:
        return 0.0
    ha, _ = np.histogram(a, bins=bins)
    hb, _ = np.histogram(b, bins=bins)
    pa = ha.astype(np.float64); pb = hb.astype(np.float64)
    pa = pa / (pa.sum() + 1e-12)
    pb = pb / (pb.sum() + 1e-12)
    return float(np.sum(np.abs(pa - pb)))


# -------------------------
# PCAP reading / analysis
# -------------------------

def open_pcap(path: str):
    f = open(path, "rb")
    try:
        r = dpkt.pcapng.Reader(f)
        return f, r
    except (ValueError, dpkt.dpkt.NeedData):
        f.seek(0)
        r = dpkt.pcap.Reader(f)
        return f, r


def analyze_pcap(
    pcap_path: str,
    rules: List[Rule],
    metric: str,
    tz_offset_hours: float,
    max_packets: int,
    quiet: bool,
) -> Dict[str, Any]:
    """
    Analyze one pcap:
      pass1 builds directional flow state
      pass2 labels packets and collects lengths
    Returns both summary stats and raw arrays for comparison.
    """
    # pass1: flow state
    payload_bytes_dir: Dict[Tuple[str, int, str, int, int], int] = {}
    rst_pkts_dir: Dict[Tuple[str, int, str, int, int], int] = {}

    f, r = open_pcap(pcap_path)
    pkt_count = 0
    try:
        for ts, buf in r:
            pkt_count += 1
            if max_packets and pkt_count > max_packets:
                break
            fields = get_packet_fields(ts, buf)
            if fields is None:
                continue
            fk = make_flow_key(fields)
            if fk is None:
                continue
            payload_bytes_dir[fk] = payload_bytes_dir.get(fk, 0) + int(fields.get("tcp_payload_len", 0) or 0)
            if fields.get("tcp_rst", 0):
                rst_pkts_dir[fk] = rst_pkts_dir.get(fk, 0) + 1
            if (not quiet) and (pkt_count % 500000 == 0):
                eprint(f"[{os.path.basename(pcap_path)} pass1] processed packets: {pkt_count}")
    finally:
        f.close()

    # pass2: label + collect lengths
    lengths_overall: List[int] = []
    lengths_by_label: Dict[str, List[int]] = {}
    benign_lengths_overall: List[int] = []
    benign_lengths_by_label: Dict[str, List[int]] = {}
    benign_label = "BENIGN"
    benign_count = 0

    f, r = open_pcap(pcap_path)
    pkt_count2 = 0
    matched = 0
    try:
        for ts, buf in r:
            pkt_count2 += 1
            if max_packets and pkt_count2 > max_packets:
                break
            fields = get_packet_fields(ts, buf)
            if fields is None:
                continue

            if metric == "caplen":
                plen = int(fields["caplen"])
            else:
                plen = int(fields["iplen"]) if fields["iplen"] is not None else int(fields["caplen"])

            label = None
            for rule in rules:
                if eval_rule(rule, fields, payload_bytes_dir, rst_pkts_dir):
                    label = rule.label
                    break
            if label is None:
                benign_count += 1
                benign_lengths_overall.append(plen)
                benign_lengths_by_label.setdefault(benign_label, []).append(plen)  # optional
                continue

            matched += 1
            lengths_overall.append(plen)
            lengths_by_label.setdefault(label, []).append(plen)

            if (not quiet) and (matched % 200000 == 0):
                eprint(f"[{os.path.basename(pcap_path)} pass2] matched packets: {matched}")
    finally:
        f.close()

    overall_arr = np.array(lengths_overall, dtype=np.int64)
    by_label_arr = {k: np.array(v, dtype=np.int64) for k, v in lengths_by_label.items()}
    benign_arr = np.array(benign_lengths_overall, dtype=np.int64)


    out = {
        "pcap": pcap_path,
        "metric": metric,
        "tz_offset_hours": tz_offset_hours,
        "packets_read": pkt_count2,
        "packets_matched": matched,
        "overall_stats": compute_stats(overall_arr),
        "by_label_stats": {k: compute_stats(v) for k, v in by_label_arr.items()},
        "overall_arr": overall_arr,
        "by_label_arr": by_label_arr,
        "overall_topk": top_k_freq(overall_arr, k=10),
    }
    out.update({
        "packets_unmatched": benign_count,                 
        "benign_overall_stats": compute_stats(benign_arr), 
        "benign_overall_arr": benign_arr,                  
        "benign_overall_topk": top_k_freq(benign_arr, k=10),
    }) 
    return out


# -------------------------
# Reporting / plotting
# -------------------------

def fmt_num(v: Any) -> str:
    if isinstance(v, float):
        if math.isinf(v):
            return "inf"
        if math.isnan(v):
            return "nan"
        return f"{v:.4f}"
    return str(v)


def print_side_by_side_stats(title: str, st_a: Dict[str, Any], st_b: Dict[str, Any]) -> None:
    keys = [
        "count", "mean", "var", "std", "min", "q1", "median", "q3", "iqr",
        "p90", "p95", "p99", "max", "mad", "cv", "skew", "kurtosis_excess"
    ]
    print(title)
    if st_a.get("count", 0) == 0 and st_b.get("count", 0) == 0:
        print("  (both empty)")
        return
    line_a = "  before: " + "  ".join([f"{k}={fmt_num(st_a.get(k, ''))}" for k in keys])
    line_b = "  after : " + "  ".join([f"{k}={fmt_num(st_b.get(k, ''))}" for k in keys])
    print(line_a)
    print(line_b)


def compare_arrays(a: np.ndarray, b: np.ndarray, bins: np.ndarray) -> Dict[str, Any]:
    """
    Compute comparison metrics for two samples.
    """
    out: Dict[str, Any] = {}
    if a.size == 0 or b.size == 0:
        return {"note": "empty sample"}
    st_a = compute_stats(a)
    st_b = compute_stats(b)
    out["delta_mean"] = float(st_b["mean"] - st_a["mean"])
    out["ratio_var"] = float(st_b["var"] / (st_a["var"] + 1e-12))
    out["delta_p90"] = float(st_b["p90"] - st_a["p90"])
    out["delta_p99"] = float(st_b["p99"] - st_a["p99"])
    out["cohen_d"] = cohen_d(a, b)
    out["ks"] = ks_statistic(a, b)
    out["js_div"] = js_divergence_hist(a, b, bins=bins)
    out["l1_hist"] = l1_distance_hist(a, b, bins=bins)

    # Some interpretable “mass” indicators:
    # - share at the mode(s)
    top_a = top_k_freq(a, k=5)
    top_b = top_k_freq(b, k=5)
    out["top5_before"] = top_a
    out["top5_after"] = top_b
    return out


def print_compare_metrics(title: str, m: Dict[str, Any]) -> None:
    print(title)
    if "note" in m:
        print(f"  {m['note']}")
        return
    print(
        "  "
        f"Δmean={fmt_num(m['delta_mean'])}  "
        f"var_ratio={fmt_num(m['ratio_var'])}  "
        f"Δp90={fmt_num(m['delta_p90'])}  "
        f"Δp99={fmt_num(m['delta_p99'])}  "
        f"Cohen_d={fmt_num(m['cohen_d'])}  "
        f"KS={fmt_num(m['ks'])}  "
        f"JS={fmt_num(m['js_div'])}  "
        f"L1_hist={fmt_num(m['l1_hist'])}"
    )
    print("  top5(before): " + ", ".join([f"{v}:{c}({r:.2%})" for v, c, r in m["top5_before"]]))
    print("  top5(after) : " + ", ".join([f"{v}:{c}({r:.2%})" for v, c, r in m["top5_after"]]))


def maybe_plot_histograms(
    plot_dir: str,
    title: str,
    a: np.ndarray,
    b: np.ndarray,
    bins: np.ndarray,
    label_a: str,
    label_b: str,
    filename: str,
) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception:
        eprint("[WARN] matplotlib not available; skip plotting.")
        return

    os.makedirs(plot_dir, exist_ok=True)

    plt.figure()
    plt.hist(a, bins=bins, alpha=0.5, label=label_a)
    plt.hist(b, bins=bins, alpha=0.5, label=label_b)
    plt.title(title)
    plt.xlabel("packet length")
    plt.ylabel("count")
    plt.legend()
    outpath = os.path.join(plot_dir, filename)
    plt.savefig(outpath, dpi=150, bbox_inches="tight")
    plt.close()


def main():
    ap = argparse.ArgumentParser(
        description="Compare packet-length stats for YAML-matched packets between two PCAPs (before vs after)."
    )
    ap.add_argument("before_pcap", help="Path to original pcap/pcapng")
    ap.add_argument("after_pcap", help="Path to perturbed pcap/pcapng")
    ap.add_argument("--yaml", default=DEFAULT_YAML, help=f"Path to rule YAML (default: {DEFAULT_YAML})")
    ap.add_argument("--metric", choices=["caplen", "iplen"], default="caplen",
                    help="Packet size metric: caplen=len(record) or iplen=IP total length")
    ap.add_argument("--tz-offset", type=float, default=0.0,
                    help="Interpret YAML timestamps as UTC+offset hours. Default 0 (UTC).")
    ap.add_argument("--max-packets", type=int, default=0,
                    help="Optional cap on packets read per pcap (0 means no limit).")
    ap.add_argument("--quiet", action="store_true", help="Less stderr progress output.")
    ap.add_argument("--json", dest="json_out", action="store_true",
                    help="Output JSON (includes per-label comparison metrics).")
    ap.add_argument("--top-labels", type=int, default=10,
                    help="How many top labels to print/plot (sorted by max(before_count, after_count)).")
    ap.add_argument("--bins", type=int, default=50,
                    help="Histogram bins for JS/L1 and plotting.")
    ap.add_argument("--plot-dir", default="",
                    help="If set, write comparison histograms (PNG) into this directory.")
    args = ap.parse_args()

    for p in [args.before_pcap, args.after_pcap, args.yaml]:
        if not os.path.isfile(p):
            eprint(f"[FATAL] file not found: {p}")
            sys.exit(2)

    rules = compile_rules(args.yaml, args.tz_offset)
    if not rules:
        eprint("[FATAL] No rules found in yaml.")
        sys.exit(2)

    before = analyze_pcap(
        pcap_path=args.before_pcap,
        rules=rules,
        metric=args.metric,
        tz_offset_hours=args.tz_offset,
        max_packets=args.max_packets,
        quiet=args.quiet,
    )
    after = analyze_pcap(
        pcap_path=args.after_pcap,
        rules=rules,
        metric=args.metric,
        tz_offset_hours=args.tz_offset,
        max_packets=args.max_packets,
        quiet=args.quiet,
    )

    # Build shared bins for histogram-based metrics & plots.
    arrs = [
        before["overall_arr"], after["overall_arr"],
        before["benign_overall_arr"], after["benign_overall_arr"],
    ]
    arrs = [a for a in arrs if a is not None and a.size > 0]
    all_for_bins = np.concatenate(arrs) if arrs else np.array([], dtype=np.int64)

    if all_for_bins.size == 0:
        eprint("[FATAL] No packets to build bins (both matched and benign are empty).")
        sys.exit(1)

    mn = int(all_for_bins.min())
    mx = int(all_for_bins.max())
    bins = np.linspace(mn, mx + 1, args.bins + 1)

    # Overall report
    header = {
        "yaml": args.yaml,
        "metric": args.metric,
        "tz_offset_hours": args.tz_offset,
        "before_pcap": args.before_pcap,
        "after_pcap": args.after_pcap,
        "before_read": before["packets_read"],
        "before_matched": before["packets_matched"],
        "after_read": after["packets_read"],
        "after_matched": after["packets_matched"],
    }

    overall_cmp = compare_arrays(before["overall_arr"], after["overall_arr"], bins=bins)
    benign_cmp = compare_arrays(before["benign_overall_arr"], after["benign_overall_arr"], bins=bins)

    # Validation A: does attack become closer to benign after perturbation?
    attack_vs_benign_before = compare_arrays(before["overall_arr"], before["benign_overall_arr"], bins=bins)
    attack_vs_benign_after  = compare_arrays(after["overall_arr"],  after["benign_overall_arr"],  bins=bins)

    # Optional: quantify improvement (negative means closer if using distance-like metrics)
    improve = {}
    if "note" not in attack_vs_benign_before and "note" not in attack_vs_benign_after:
        improve = {
            "delta_KS": float(attack_vs_benign_after["ks"] - attack_vs_benign_before["ks"]),
            "delta_JS": float(attack_vs_benign_after["js_div"] - attack_vs_benign_before["js_div"]),
            "delta_L1": float(attack_vs_benign_after["l1_hist"] - attack_vs_benign_before["l1_hist"]),
    }

    # Per-label comparison (union of labels)
    labels = set(before["by_label_arr"].keys()) | set(after["by_label_arr"].keys())
    label_rows = []
    for lab in labels:
        a = before["by_label_arr"].get(lab, np.array([], dtype=np.int64))
        b = after["by_label_arr"].get(lab, np.array([], dtype=np.int64))
        st_a = compute_stats(a)
        st_b = compute_stats(b)
        label_rows.append((lab, max(st_a.get("count", 0), st_b.get("count", 0))))

    label_rows.sort(key=lambda x: x[1], reverse=True)
    top_labels = [lab for lab, _ in label_rows[: max(0, args.top_labels)]]

    per_label_cmp: Dict[str, Any] = {}
    for lab in top_labels:
        a = before["by_label_arr"].get(lab, np.array([], dtype=np.int64))
        b = after["by_label_arr"].get(lab, np.array([], dtype=np.int64))
        per_label_cmp[lab] = compare_arrays(a, b, bins=bins)

    if args.json_out:
        out = {
            "meta": header,
            "before_overall": before["overall_stats"],
            "after_overall": after["overall_stats"],
            "overall_compare": overall_cmp,
            "before_top10_lengths": before["overall_topk"],
            "after_top10_lengths": after["overall_topk"],
            "per_label_compare_top": per_label_cmp,
        }
        out.update({
            "before_benign_overall": before["benign_overall_stats"],
            "after_benign_overall": after["benign_overall_stats"],
            "benign_overall_compare": benign_cmp,
            "before_benign_top10_lengths": before["benign_overall_topk"],
            "after_benign_top10_lengths": after["benign_overall_topk"],
        })
        out.update({
            "attack_vs_benign_before": attack_vs_benign_before,
            "attack_vs_benign_after": attack_vs_benign_after,
            "validationA_improve": improve,
        })
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    # Human-readable output
    print(f"YAML:   {header['yaml']}")
    print(f"Metric: {header['metric']}   (caplen=len(record), iplen=IP total length)")
    print(f"Time:   interpret YAML as UTC+{header['tz_offset_hours']} hours")
    print(f"Before: {header['before_pcap']}")
    print(f"  read={header['before_read']} matched={header['before_matched']}")
    print(f"After : {header['after_pcap']}")
    print(f"  read={header['after_read']} matched={header['after_matched']}")
    print()

    print_side_by_side_stats("[OVERALL STATS]", before["overall_stats"], after["overall_stats"])
    print()
    print_compare_metrics("[OVERALL COMPARE]", overall_cmp)
    print()

    print_side_by_side_stats("[BENIGN OVERALL STATS]", before["benign_overall_stats"], after["benign_overall_stats"])
    print_compare_metrics("[BENIGN OVERALL COMPARE]", benign_cmp)
    print()
    print("[BENIGN TOP-10 LENGTHS]")
    print("  before: " + ", ".join([f"{v}:{c}({r:.2%})" for v, c, r in before["benign_overall_topk"]]))
    print("  after : " + ", ".join([f"{v}:{c}({r:.2%})" for v, c, r in after["benign_overall_topk"]]))
    print()

    print("[OVERALL TOP-10 LENGTHS] (value:count(ratio))")
    print("  before: " + ", ".join([f"{v}:{c}({r:.2%})" for v, c, r in before["overall_topk"]]))
    print("  after : " + ", ".join([f"{v}:{c}({r:.2%})" for v, c, r in after["overall_topk"]]))
    print()

    print(f"[BY LABEL] top={len(top_labels)} labels (sorted by max(before_count, after_count) desc)")
    for lab in top_labels:
        st_a = before["by_label_stats"].get(lab, {"count": 0})
        st_b = after["by_label_stats"].get(lab, {"count": 0})
        print_side_by_side_stats(f"- {lab}", st_a, st_b)
        print_compare_metrics(f"  compare({lab})", per_label_cmp[lab])
        print()

    print_compare_metrics("[ATTACK vs BENIGN DISTANCE | BEFORE]", attack_vs_benign_before)
    print_compare_metrics("[ATTACK vs BENIGN DISTANCE | AFTER ]", attack_vs_benign_after)

    if improve:
        print("[VALIDATION A RESULT] (negative delta means closer to benign)")
        print(f"  ΔKS={fmt_num(improve['delta_KS'])}  ΔJS={fmt_num(improve['delta_JS'])}  ΔL1={fmt_num(improve['delta_L1'])}")
    print()

    # Optional plots
    if args.plot_dir:
        maybe_plot_histograms(
            plot_dir=args.plot_dir,
            title="OVERALL length distribution (matched packets)",
            a=before["overall_arr"],
            b=after["overall_arr"],
            bins=bins,
            label_a="before",
            label_b="after",
            filename="overall_hist.png",
        )
        for lab in top_labels:
            a = before["by_label_arr"].get(lab, np.array([], dtype=np.int64))
            b = after["by_label_arr"].get(lab, np.array([], dtype=np.int64))
            if a.size == 0 and b.size == 0:
                continue
            safe_name = "".join(ch if ch.isalnum() else "_" for ch in lab)[:120]
            maybe_plot_histograms(
                plot_dir=args.plot_dir,
                title=f"{lab} length distribution (matched packets)",
                a=a,
                b=b,
                bins=bins,
                label_a="before",
                label_b="after",
                filename=f"label_{safe_name}.png",
            )
            maybe_plot_histograms(
                plot_dir=args.plot_dir,
                title="BENIGN length distribution (unmatched packets)",
                a=before["benign_overall_arr"],
                b=after["benign_overall_arr"],
                bins=bins,
                label_a="before_benign",
                label_b="after_benign",
                filename="benign_hist.png",
            )
        eprint(f"[INFO] plots saved to: {args.plot_dir}")


if __name__ == "__main__":
    main()
