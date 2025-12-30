# pcaplab/match.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Set

@dataclass
class AttackMatcher:
    time_ranges: List[Tuple[float, float]] = field(default_factory=list)  # inclusive
    ips: Set[str] = field(default_factory=set)
    match_on: str = "either"  # src|dst|either

    def is_attack(self, ts: float, src_ip: Optional[str], dst_ip: Optional[str]) -> bool:
        if self.time_ranges:
            if not any(a <= ts <= b for a, b in self.time_ranges):
                return False
        if self.ips:
            if self.match_on == "src":
                return src_ip in self.ips
            if self.match_on == "dst":
                return dst_ip in self.ips
            return (src_ip in self.ips) or (dst_ip in self.ips)
        # only time range -> ok; neither -> treat as "match all" handled by caller
        return True

def parse_time_ranges(items) -> List[Tuple[float, float]]:
    out = []
    for s in items or []:
        a_str, b_str = [x.strip() for x in str(s).split(",")]
        a, b = float(a_str), float(b_str)
        if b < a:
            a, b = b, a
        out.append((a, b))
    return out
