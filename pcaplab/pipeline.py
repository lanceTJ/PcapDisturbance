import random, math
from collections import defaultdict, Counter
from typing import Iterable, List, Dict, Any
from .stream import stream_pcap_packets, parse_packet, PcapSink, PcapSinkBuffered
from .perturbations import PERTURBATIONS
from .utils import log

def _apply_plans_to_packet(pkt, plans: List[dict], rng: random.Random, stats: Dict[str,int]):
    """
    Apply a set of perturbation plans to one packet.
    Each plan independently fires with probability pct.
    Return a list[packet] (possibly empty if dropped).
    """
    modified = [pkt]
    for plan in plans:
        typ  = plan.get("type")
        pct  = float(plan.get("pct", 0.0))
        params = plan.get("params", {}) or {}
        if rng.random() >= pct:
            continue
        fn = PERTURBATIONS.get(typ)
        stats[f"applied_{typ}"] += 1
        if fn is None:
            continue
        res = fn(pkt, **params) if params else fn(pkt)
        if res is None:     # dropped
            stats[f"dropped_{typ}"] += 1
            return []       # stop chain once dropped
        if isinstance(res, list):
            modified = res   # replace with returned list
        else:
            modified = [res]
    return modified

def apply_perturbations_stream(
    in_pcap: str,
    out_pcap: str,
    perturb_plan: List[dict],
    selection_seed: int = 0,
    chunk_size: int = 10000,
    show_progress: bool = False,
    progress_every: int = 200_000, 
):
    rng = random.Random(selection_seed)
    sink = PcapSinkBuffered(out_pcap, append=False)
    total_in = 0
    total_out = 0
    stats = defaultdict(int)

    buf: List[bytes] = []

    try:
        for item in stream_pcap_packets(in_pcap):
            pkt_bytes = item[0] if isinstance(item, tuple) else item
            buf.append(pkt_bytes)

            if len(buf) >= chunk_size:
                _in, _out = _process_chunk(buf, sink, perturb_plan, rng, stats)
                total_in += _in
                total_out += _out
                if show_progress and (total_in // progress_every != (total_in - _in) // progress_every):
                    log.info(f"[progress] {in_pcap}  in={total_in} out={total_out}")
                buf.clear()

        if buf:
            _in, _out = _process_chunk(buf, sink, perturb_plan, rng, stats)
            total_in += _in
            total_out += _out
            if show_progress:
                log.info(f"[progress] {in_pcap}  in={total_in} out={total_out}")

    finally:
        try:
            sink.close()
        except Exception:
            pass

    return {"total_in": total_in, "total_out": total_out, "stats": dict(stats)}


def _process_chunk(raw_list: List[bytes], sink: PcapSink, plans, rng, stats) -> (int,int):
    parsed = [parse_packet(b) for b in raw_list]
    out_pkts = 0
    for pkt in parsed:
        stats["in"] += 1
        modified = _apply_plans_to_packet(pkt, plans, rng, stats)
        for mp in modified:
            sink.write(mp)
            stats["out"] += 1
            out_pkts += 1
    return len(parsed), out_pkts
