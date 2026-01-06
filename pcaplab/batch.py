# pcaplab/batch.py
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp
from typing import List, Dict, Any, Tuple
import time
from .pipeline import apply_perturbations_stream
from .utils import ensure_dir, is_encrypted_dir, log, now_iso
from .length_pool import BenignLengthSampler
from .stream import stream_pcap_packets_fast

def collect_pcaps(in_root: Path) -> list[Path]:
    """Collect all files starting with 'cap' (no extension dependency)."""
    pcaps = []
    for root, dirs, files in os_walk_skip_encrypted(in_root):
        for f in files:
            if f.startswith("cap"):          # Simple prefix check
                pcaps.append(Path(root) / f)
    return pcaps

def os_walk_skip_encrypted(in_root: Path):
    import os
    for root, dirs, files in os.walk(in_root):
        dirs[:] = [d for d in dirs if not is_encrypted_dir(Path(d))]
        yield root, dirs, files

def _maybe_build_workflow_benign_sampler(pcaps: list[Path], plan: list[dict], selection_seed: int) -> BenignLengthSampler | None:
    # Find the first TM2 length_forge step that does NOT use YAML matcher
    cfg = None
    for step in plan:
        t = str(step.get("type", "")).lower()
        if t not in {"length_forge", "length-forge", "lenfake"}:
            continue
        params = step.get("params", {}) or {}
        strategy = str(params.get("strategy", "fixed")).lower().strip()
        if strategy in {"tm2", "benign_pool", "pool"} and not params.get("match"):
            cfg = params
            break

    if cfg is None:
        return None

    benign_keywords = [str(x).lower() for x in cfg.get("benign_name_keywords", ["benign", "normal"])]
    min_len = int(cfg.get("min_len", 60))
    max_len = int(cfg.get("max_len", 1514))
    max_pkts_per_pcap = int(cfg.get("max_pkts_per_pcap", 0))

    sampler = BenignLengthSampler(min_len=min_len, max_len=max_len, seed=int(selection_seed))

    benign_pcaps = [p for p in pcaps if any(k in p.name.lower() for k in benign_keywords)]
    if not benign_pcaps:
        raise ValueError(f"TM2 workflow benign pool requested, but no benign pcaps matched keywords={benign_keywords}")

    for p in benign_pcaps:
        n = 0
        for _ts, pkt in stream_pcap_packets_fast(str(p)):
            sampler.ingest_len(len(pkt))
            n += 1
            if max_pkts_per_pcap > 0 and n >= max_pkts_per_pcap:
                break

    sampler.finalize()
    return sampler

def _out_paths(in_pcap: Path, in_root: Path, out_root: Path):
    """
    Output rules:
      - Keep input filename as is (even without extension),
      - Append .pcap as output suffix.
      - Metadata uses original name + ".metadata.json".
    """
    rel = in_pcap.relative_to(in_root)
    date_dir = rel.parts[0] if len(rel.parts) >= 1 else "unknown_date"
    out_dir = out_root / date_dir

    base_name = in_pcap.name                 # e.g., capDESKTOP-AN3U28N-172.31.64.17
    out_name = f"{base_name}.pcap"           # -> capDESKTOP-AN3U28N-172.31.64.17.pcap

    out_pcap = out_dir / out_name
    meta     = out_dir / f"{base_name}.metadata.json"
    return date_dir, out_dir, out_pcap, meta

def process_single_pcap(in_pcap: Path, in_root: Path, out_root: Path,
                        plan: List[Dict[str,Any]],
                        chunk_size=10000, selection_seed=0, verbose=False,
                        resume=False, workflow_benign_sampler=None) -> Dict[str,Any]:
    date_dir, out_dir, out_pcap, meta_path = _out_paths(in_pcap, in_root, out_root)
    ensure_dir(out_dir)
    if resume and out_pcap.exists():
        return {"input": str(in_pcap), "output": str(out_pcap), "date_dir": date_dir,
                "skipped": True, "reason":"exists"}

    t0 = time.time()
    res = apply_perturbations_stream(
        in_pcap=str(in_pcap),
        out_pcap=str(out_pcap),
        perturb_plan=plan,
        selection_seed=selection_seed,
        chunk_size=chunk_size,
        show_progress=False,
        workflow_benign_sampler=workflow_benign_sampler,
    )
    dur = time.time() - t0
    meta = {
        "pcap_file": in_pcap.name,
        "input": str(in_pcap),
        "output": str(out_pcap),
        "date_dir": date_dir,
        "plan": plan,
        "selection_seed": selection_seed,
        "chunk_size": chunk_size,
        "timestamp": now_iso(),
        "elapsed_sec": round(dur, 3),
        "stats": res,
    }
    log.debug(f"Metadata for {in_pcap.name}: {meta}")
    return meta

def _task(args):
    return process_single_pcap(*args)

def _run_common(pcaps, in_root, out_root, plan, chunk_size, selection_seed,
                workers, verbose, resume, executor_factory):
    tasks = [(p, in_root, out_root, plan, chunk_size, selection_seed, verbose, resume) for p in pcaps]
    results = []
    with executor_factory(max_workers=workers) as ex:
        fut2p = {ex.submit(_task, t): t[0] for t in tasks}
        for fut in as_completed(fut2p):
            p = fut2p[fut]
            try:
                r = fut.result()
                results.append(r)
                if verbose:
                    if r.get("skipped"):
                        log.info(f"[SKIP] {p.name} -> exists")
                    else:
                        log.info(f"[DONE] {p.name} in {r.get('elapsed_sec','?')}s  "
                                 f"in={r['stats'].get('total_in','?')} out={r['stats'].get('total_out','?')}")
            except Exception as e:
                results.append({"status":"error","input":str(p),"error":str(e)})
                log.error(f"[FAIL] {p.name}: {e}")
    return results

def run_threads(in_root: Path, out_root: Path, plan: List[Dict[str,Any]],
                chunk_size=10000, selection_seed=0, workers=4, limit=None, verbose=False, resume=False, per_file_log=False):
    pcaps = collect_pcaps(in_root)
    workflow_sampler = _maybe_build_workflow_benign_sampler(pcaps, plan, selection_seed)
    if limit: pcaps = pcaps[:limit]
    if workers <= 1:
        from concurrent.futures import Executor
        class _S(Executor):
            def __enter__(self): return self
            def __exit__(self,*a): pass
            def submit(self, fn, *args, **kwargs):
                from concurrent.futures import Future
                f = Future()
                try: f.set_result(fn(*args, **kwargs))
                except Exception as e: f.set_exception(e)
                return f
        executor_factory = lambda max_workers: _S()
    else:
        executor_factory = lambda max_workers: ThreadPoolExecutor(max_workers=max_workers)
    return _run_common(pcaps, in_root, out_root, plan, chunk_size, selection_seed,
                       workers, verbose or per_file_log, resume, executor_factory)

def run_processes(in_root: Path, out_root: Path, plan, chunk_size=10000,
                  selection_seed=0, workers=2, limit=None,
                  verbose=False, resume=False, per_file_log=False):
    pcaps = collect_pcaps(in_root)
    if limit: pcaps = pcaps[:limit]

    import multiprocessing as mp
    from concurrent.futures import ProcessPoolExecutor, as_completed
    ctx = mp.get_context("spawn")

    tasks = [(p, in_root, out_root, plan, chunk_size, selection_seed, verbose, resume) for p in pcaps]
    results = []
    try:
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as ex:
            fut2p = {ex.submit(_task, t): t[0] for t in tasks}
            for fut in as_completed(fut2p):
                p = fut2p[fut]
                try:
                    r = fut.result()
                    results.append(r)
                    if verbose or per_file_log:
                        if r.get("skipped"):
                            log.info(f"[SKIP] {p.name} -> exists")
                        else:
                            log.info(f"[DONE] {p.name} in {r.get('elapsed_sec','?')}s "
                                     f"in={r['stats'].get('total_in','?')} out={r['stats'].get('total_out','?')}")
                except Exception as e:
                    results.append({"status":"error","input":str(p),"error":str(e)})
                    log.error(f"[FAIL] {p.name}: {e}")
    except KeyboardInterrupt:
        log.warning("Interrupted by user, cancelling remaining tasks...")
    return results