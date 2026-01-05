# pcaplab/cli.py (Unchanged, but ensure plan parsing supports pad_byte str)
import json, argparse
from pathlib import Path
from .batch import run_threads, run_processes
from .utils import log

def parse_plan_from_args(args) -> list:
    plan = []
    if args.loss is not None:
        plan.append({"type":"loss", "pct": float(args.loss), "params": {}})
    if args.retransmit is not None:
        plan.append({"type":"retransmit", "pct": float(args.retransmit), "params": {}})
    if args.seq_offset:
        pct, off = args.seq_offset.split(":")
        plan.append({"type":"seq_offset", "pct": float(pct), "params": {"offset": int(off)}})
    if args.length_forge:
        pct, ln = args.length_forge.split(":")
        plan.append({"type":"length_forge", "pct": float(pct), "params": {"new_len": int(ln)}})
    if args.plan:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    if not plan:
        raise SystemExit("No perturbation specified. Use --loss/--seq-offset/--length-forge or --plan.")
    return plan

def main():
    p = argparse.ArgumentParser(prog="pcaplab", description="PCAP perturbation batch runner")
    p.add_argument("--in-root", required=True)
    p.add_argument("--out-root", required=True)
    p.add_argument("--backend", choices=["threads", "processes"], default="threads")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--chunk-size", type=int, default=10000)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--resume", dest="resume", action="store_true",
                  help="Skip files whose output pcap already exists")

    # quick plan flags
    p.add_argument("--loss", type=float)
    p.add_argument("--retransmit", type=float)
    p.add_argument("--seq-offset", dest="seq_offset", help="pct:offset, e.g. 0.02:500")
    p.add_argument("--length-forge", dest="length_forge", help="pct:newlen, e.g. 0.01:512")
    p.add_argument("--plan", help="JSON plan (overrides quick flags)")

    args = p.parse_args()

    plan = parse_plan_from_args(args)
    in_root = Path(args.in_root).resolve()
    out_root = Path(args.out_root).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    runner = run_threads if args.backend == "threads" else run_processes

    results = runner(
        in_root=in_root,
        out_root=out_root,
        plan=plan,
        chunk_size=args.chunk_size,
        selection_seed=args.seed,
        workers=args.workers,
        limit=args.limit,
        verbose=args.verbose,
        resume=args.resume,
        per_file_log=args.verbose
    )

    # brief summary
    # print(json.dumps(results[:10], indent=2, ensure_ascii=False))