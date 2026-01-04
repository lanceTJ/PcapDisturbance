# pcaplab/rule_matcher.py
from __future__ import annotations

import functools
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import dpkt
import yaml


# ----------------------------
# Time parsing
# ----------------------------

def _parse_iso_utc(s: str) -> float:
    """
    Parse ISO8601 string (with or without Z / timezone) as UTC epoch seconds.
    Your CIC2018 rule file states times are UTC.
    """
    s = str(s).strip()
    # Accept "2018-03-02T19:54:52" or "...Z" or "...+00:00"
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.timestamp()


# ----------------------------
# Packet parsing (minimal L2/L3/L4)
# ----------------------------

@dataclass(frozen=True)
class PacketCtx:
    ts: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    proto: Optional[str]      # "tcp"/"udp"/"icmp"/None
    src_port: Optional[int]
    dst_port: Optional[int]


def _pkt_ctx(ts: float, buf: bytes) -> PacketCtx:
    src_ip = dst_ip = None
    proto_s: Optional[str] = None
    sport = dport = None

    try:
        eth = dpkt.ethernet.Ethernet(buf)
        payload = eth.data

        # VLAN unwrap
        if isinstance(payload, dpkt.ethernet.VLANtag8021Q):
            payload = payload.data

        ip = payload
        if isinstance(ip, dpkt.ip.IP):
            src_ip = ".".join(map(str, ip.src))
            dst_ip = ".".join(map(str, ip.dst))
            p = ip.p
            l4 = ip.data
        elif isinstance(ip, dpkt.ip6.IP6):
            # dpkt gives raw 16 bytes; use ipaddress for formatting
            import ipaddress
            src_ip = str(ipaddress.IPv6Address(ip.src))
            dst_ip = str(ipaddress.IPv6Address(ip.dst))
            p = ip.nxt
            l4 = ip.data
        else:
            return PacketCtx(ts, None, None, None, None, None)

        if p == dpkt.ip.IP_PROTO_TCP and isinstance(l4, dpkt.tcp.TCP):
            proto_s = "tcp"
            sport, dport = int(l4.sport), int(l4.dport)
        elif p == dpkt.ip.IP_PROTO_UDP and isinstance(l4, dpkt.udp.UDP):
            proto_s = "udp"
            sport, dport = int(l4.sport), int(l4.dport)
        elif p == dpkt.ip.IP_PROTO_ICMP:
            proto_s = "icmp"
        elif p == dpkt.ip.IP_PROTO_ICMP6:
            proto_s = "icmp"
        else:
            # Other protocol: keep proto None to avoid false positives on port constraints
            proto_s = None

    except Exception:
        return PacketCtx(ts, None, None, None, None, None)

    return PacketCtx(ts, src_ip, dst_ip, proto_s, sport, dport)


# ----------------------------
# Rule compilation (packet-level subset)
# ----------------------------

def _normalize_field_name(field: str) -> str:
    f = str(field).strip().lower()
    # YAML uses any_ip sometimes; normalize both any_ip/any_ip(s)
    if f in {"any_ip", "any_ips"}:
        return "any_ip"
    return f


def _op_in(val, candidates: Sequence[Any]) -> bool:
    return val in candidates


def _op_not_in(val, candidates: Sequence[Any]) -> bool:
    return val not in candidates


def _op_eq(val, rhs) -> bool:
    return val == rhs


def _op_neq(val, rhs) -> bool:
    return val != rhs


def _op_range(ts: float, start_end: Sequence[Any]) -> bool:
    a, b = start_end
    a_ts = _parse_iso_utc(a) if isinstance(a, str) else float(a)
    b_ts = _parse_iso_utc(b) if isinstance(b, str) else float(b)
    if b_ts < a_ts:
        a_ts, b_ts = b_ts, a_ts
    return a_ts <= ts <= b_ts


def _op_ranges(ts: float, ranges: Sequence[Sequence[Any]]) -> bool:
    return any(_op_range(ts, r) for r in ranges)


@dataclass(frozen=True)
class CompiledRule:
    label: str
    priority: int
    fn: Any  # callable(PacketCtx)->bool


def _compile_conditions(match_list: List[Dict[str, Any]]):
    """
    Compile a rule's 'match' list into a predicate on PacketCtx.
    Supported (packet-level) fields:
      - src_ip, dst_ip, any_ip
      - src_port, dst_port
      - proto
      - time_window (op: range/ranges)
    Unsupported (flow-level) fields are ignored.
    """
    conds = []

    for cond in match_list or []:
        field = _normalize_field_name(cond.get("field"))
        op = str(cond.get("op")).strip().lower()
        value = cond.get("value")

        # time window
        if field == "time_window":
            if op == "range":
                conds.append(lambda ctx, v=value: _op_range(ctx.ts, v))
            elif op == "ranges":
                conds.append(lambda ctx, v=value: _op_ranges(ctx.ts, v))
            else:
                # unsupported time op -> ignore
                continue
            continue

        # IP fields
        if field in {"src_ip", "dst_ip", "any_ip"}:
            if op in {"in", "not_in"} and not isinstance(value, (list, tuple)):
                value = [value]

            if field == "src_ip":
                if op == "in":
                    conds.append(lambda ctx, v=value: ctx.src_ip is not None and _op_in(ctx.src_ip, v))
                elif op == "not_in":
                    conds.append(lambda ctx, v=value: ctx.src_ip is not None and _op_not_in(ctx.src_ip, v))
                elif op == "==":
                    conds.append(lambda ctx, v=value: ctx.src_ip == v)
                elif op == "!=":
                    conds.append(lambda ctx, v=value: ctx.src_ip != v)
                continue

            if field == "dst_ip":
                if op == "in":
                    conds.append(lambda ctx, v=value: ctx.dst_ip is not None and _op_in(ctx.dst_ip, v))
                elif op == "not_in":
                    conds.append(lambda ctx, v=value: ctx.dst_ip is not None and _op_not_in(ctx.dst_ip, v))
                elif op == "==":
                    conds.append(lambda ctx, v=value: ctx.dst_ip == v)
                elif op == "!=":
                    conds.append(lambda ctx, v=value: ctx.dst_ip != v)
                continue

            # any_ip: match if either end matches
            if field == "any_ip":
                if op == "in":
                    conds.append(lambda ctx, v=value: (ctx.src_ip in v) or (ctx.dst_ip in v))
                elif op == "not_in":
                    conds.append(lambda ctx, v=value: (ctx.src_ip not in v) and (ctx.dst_ip not in v))
                elif op == "==":
                    conds.append(lambda ctx, v=value: (ctx.src_ip == v) or (ctx.dst_ip == v))
                elif op == "!=":
                    conds.append(lambda ctx, v=value: (ctx.src_ip != v) and (ctx.dst_ip != v))
                continue

        # Ports (TCP/UDP only)
        if field in {"src_port", "dst_port"}:
            if op in {"in", "not_in"} and not isinstance(value, (list, tuple)):
                value = [value]
            if field == "src_port":
                if op == "in":
                    conds.append(lambda ctx, v=value: ctx.src_port is not None and ctx.src_port in v)
                elif op == "not_in":
                    conds.append(lambda ctx, v=value: ctx.src_port is not None and ctx.src_port not in v)
                elif op == "==":
                    conds.append(lambda ctx, v=value: ctx.src_port == int(v))
                elif op == "!=":
                    conds.append(lambda ctx, v=value: ctx.src_port != int(v))
                continue
            if field == "dst_port":
                if op == "in":
                    conds.append(lambda ctx, v=value: ctx.dst_port is not None and ctx.dst_port in v)
                elif op == "not_in":
                    conds.append(lambda ctx, v=value: ctx.dst_port is not None and ctx.dst_port not in v)
                elif op == "==":
                    conds.append(lambda ctx, v=value: ctx.dst_port == int(v))
                elif op == "!=":
                    conds.append(lambda ctx, v=value: ctx.dst_port != int(v))
                continue

        # proto
        if field == "proto":
            # accept numeric or text
            if isinstance(value, (int, float)):
                # 6 tcp, 17 udp, 1 icmp (ipv4), 58 icmpv6
                mapping = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}
                want = mapping.get(int(value))
            else:
                want = str(value).strip().lower()
            if want in {"tcp", "udp", "icmp"}:
                conds.append(lambda ctx, w=want: ctx.proto == w)
            continue

        # Unsupported flow-level fields -> ignore safely
        # e.g. zero_fwd, total_fwd_len, bwd_rst_flags, flow_duration_s, ...
        continue

    def _all(ctx: PacketCtx) -> bool:
        return all(c(ctx) for c in conds)

    return _all


@functools.lru_cache(maxsize=32)
def _load_rules_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class YamlRulePacketMatcher:
    """
    Packet-level matcher backed by the 'Improved CSE-CIC-IDS2018' YAML.
    It treats a packet as "matched" if it matches ANY selected rule.
    """
    def __init__(self, rules_path: str, include_labels: Optional[Sequence[str]] = None):
        self.rules_path = rules_path
        self.include_labels = set(include_labels) if include_labels else None
        self._compiled: List[CompiledRule] = []
        self._compile()

    def _compile(self):
        doc = _load_rules_yaml(self.rules_path)
        rules = doc.get("rules", []) or []
        compiled: List[CompiledRule] = []
        for r in rules:
            label = str(r.get("label", ""))
            if self.include_labels is not None and label not in self.include_labels:
                continue
            prio = int(r.get("priority", 1_000_000))
            match_list = r.get("match", []) or []
            fn = _compile_conditions(match_list)
            compiled.append(CompiledRule(label=label, priority=prio, fn=fn))
        # Evaluate higher priority first (lower number)
        compiled.sort(key=lambda x: x.priority)
        self._compiled = compiled

    def match_packet(self, ts: float, buf: bytes) -> bool:
        ctx = _pkt_ctx(ts, buf)
        for cr in self._compiled:
            if cr.fn(ctx):
                return True
        return False
