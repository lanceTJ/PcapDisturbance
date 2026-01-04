# PcabDisturbance

PcabDisturbance is a **high-performance, dpkt-first, streaming PCAP disturbance toolkit** implementing Threat Model I/II.

Core design principles:

- **Streaming stage pipeline**: each disturbance is a stage; stages are applied sequentially.
- **Bytes-first fast path**: record-level disturbances operate on `(timestamp, raw_packet_bytes)` without protocol parsing.
- **Lazy/limited parsing**: only content-modifying disturbances (e.g., `seq_offset`) touch headers.
- **Deterministic & reproducible**: fixed seed yields repeatable results; **each stage has an independent RNG stream**
  (stage randomness is not affected by earlier stages consuming random numbers).

Supported capture format: **classic pcap** (no pcapng).

---

## Features

- Packet loss (`loss`)
- Retransmission / duplication (`retransmit` / `retrans`)
- Length forgery (`length_forge`) — **forces entire packet bytes to fixed length**
- Reorder / jitter (`reorder` / `jitter`) — **trigger-based window shuffle**, timestamps reassigned within the window
- TCP sequence offset (`seq_offset`) — modifies TCP seq and recalculates checksums
- Rate adjustment / speed change (`rate_adjust`) — **attack-only timestamp shift + reposition by timestamp**
- Directory batch runner: mirrors date/PCAP directory structure; skips `encrypted_pcaps` directories

---

## Installation

```bash
pip install -e .
````

Dependencies:

* `dpkt`

---

## Usage

### 1) Configuration Preparation

* Copy `config.example.yaml` to `config.yaml` and modify as needed.

Key fields:

* `in_root`: Input PCAP directory path (e.g., `/data/en-cic2018/pcapdata`).
* `out_root`: Output directory for disturbed PCAPs (mirrors directory structure).
* `backend`: `threads` or `processes`.
* `workers`: number of concurrent workers.
* `chunk_size`: number of packets per I/O batch (default 5000–10000 works well).
* `seed`: random seed (reproducible).
* `plan`: disturbance plan list; each step runs sequentially.

### 2) Running the Tool

Batch process via CLI:

```bash
pcaplab --in-root <input_dir> --out-root <output_dir> --backend threads --workers 4 --chunk-size 5000 --seed 42 --plan plan.json
```

Options:

* `--plan`: JSON plan file (overrides quick flags).

* Quick flags (can be used instead of `--plan`):

  * `--loss <pct>`: drop `pct` fraction of packets (e.g., `0.1` = 10%).
  * `--retransmit <pct>`: duplicate `pct` fraction of packets.
  * `--seq-offset <pct:offset>`: apply TCP seq offset to `pct` fraction of packets, e.g. `0.02:500`.
  * `--length-forge <pct:newlen>`: force packet length to `newlen` for `pct` fraction of packets, e.g. `0.01:512`.

* `--resume`: skip files whose output already exists.

* `--verbose`: detailed logs.

Example (apply reorder only):

```bash
pcaplab --in-root /data/cicids2018 --out-root /output/reordered --backend threads --workers 8 --chunk-size 10000 --seed 42 --plan reorder_plan.json
```

---

## Plan Format

Disturbances are defined in the `plan` array (either in YAML config or in a JSON plan file).
They are applied **sequentially**.

Each plan item:

* `type`: disturbance type
* `pct`: application probability / fraction (**float 0–1**)
* `params`: optional parameters dict

### Semantics Notes

* **Order matters**: later stages operate on the output of earlier stages.
* **Percentages stack**: the same packet can be affected by multiple stages.
* **Independent RNG per stage**: stage A consuming randomness does not change stage B’s selection.
* **Length forgery** operates on the **entire packet bytes**, not only payload; this may produce malformed packets for strict parsers.
* `reorder` and `rate_adjust` involve buffering/repositioning; peak memory depends on configured window sizes.

---

## Supported Disturbances

### 1) Packet Loss (`loss`)

* Randomly drops `pct` fraction of packets.
* Params: none.

```yaml
plan:
  - {type: loss, pct: 0.2, params: {}}
```

### 2) Retransmission (`retransmit` / `retrans`)

* Duplicates `pct` fraction of packets.

Params (optional):

* `copies` (default `1`): number of additional copies per selected packet
* `delay_ms` (default `0.0`): timestamp offset per copy (ms)

```yaml
plan:
  - {type: loss, pct: 0.1, params: {}}
  - {type: retransmit, pct: 0.15, params: {copies: 1, delay_ms: 0.0}}
```

### 3) Reorder / Jitter (`reorder` / `jitter`)

* With probability `pct`, a packet becomes a **trigger point**.
* The trigger packet + the **next `k` packets** are shuffled.
* Timestamps are reassigned inside the window to keep ordering in the window.

Params:

* `k` (preferred): number of packets after the trigger (window size is `k+1`)
* `m` (compat): treated as `k` if `k` not provided
* `ts_mode`:

  * `keep` (default): reuse the original timestamps (sorted) and assign to the shuffled packets
  * `linear`: interpolate timestamps from window min to max

```yaml
plan:
  - {type: reorder, pct: 0.05, params: {k: 20, ts_mode: keep}}
```

### 4) TCP Sequence Offset (`seq_offset`)

* Modifies TCP sequence numbers by `offset` for `pct` fraction of packets.
* Recalculates IP and TCP checksums (best-effort; non-IPv4/TCP packets pass through unchanged).

Params:

* `offset` (default `1000`)

```yaml
plan:
  - {type: seq_offset, pct: 0.02, params: {offset: 1000}}
```

### 5) Length Forgery (`length_forge`)

* With probability `pct`, forces the **entire packet bytes** to `new_len`:

  * If longer: truncate
  * If shorter: pad with `pad_byte`
* **No** checksum recalculation and **no** IP/TCP/UDP length-field repair.

Params:

* `new_len` (required)
* `pad_byte` (optional, default `"00"`): `"00"`, `"0x0f"`, `"15"`, etc.

Optional matching (apply only to “attack packets”):

* `params.match.time_ranges`: list of `"start,end"` (pcap timestamps, seconds; inclusive)
* `params.match.ips`: list of IP strings
* `params.match.ip_match`: `either` (default) / `src` / `dst`

```yaml
plan:
  - type: length_forge
    pct: 0.01
    params:
      new_len: 1024
      pad_byte: "0x0f"
      match:
        time_ranges: ["1700000000,1700000100"]
        ips: ["192.0.2.1"]
        ip_match: either
```

### 6) Rate Adjustment / Speed Change (`rate_adjust`)

Purpose:

* Identify “attack packets” (by time range and/or IP label),
* with probability `pct` shift their timestamp **forward** by `shift_ms`,
* then **reposition packets by (possibly modified) timestamps**.

Implementation:

* `rate_adjust` compiles into two stages:

  1. `RateAdjustStage`: adds `shift_ms` to selected attack packets’ timestamps
  2. `OnlineTimeSorter`: reorders output by timestamp under a bounded-delay assumption

Bounded-delay assumption:

* This pipeline guarantees correct online sorting if timestamps are only shifted **forward** by at most `max_delay_ms`.

Params:

* `shift_ms` (required): forward shift in milliseconds
* `max_delay_ms` (optional): upper bound on forward shift; must be `>= shift_ms` (default = `shift_ms`)
* `match` (required): attack matcher configuration

Matcher (`params.match`):

* `time_ranges`: list of `"start,end"` (pcap timestamps in seconds; inclusive)
* `ips`: list of IP strings
* `ip_match`: `either` (default) / `src` / `dst`

```yaml
plan:
  - type: rate_adjust
    pct: 0.30
    params:
      shift_ms: 50
      max_delay_ms: 50
      match:
        time_ranges: ["1700000000,1700000100"]
        ips: ["192.0.2.1"]
        ip_match: either
```

---

## Full Config Example

```yaml
in_root: /data/cicids2018
out_root: /output/perturbed
backend: threads
workers: 8
chunk_size: 10000
seed: 42
plan:
  - {type: loss, pct: 0.10, params: {}}
  - {type: retransmit, pct: 0.05, params: {copies: 1, delay_ms: 0.0}}
  - {type: reorder, pct: 0.05, params: {k: 20, ts_mode: keep}}
  - {type: seq_offset, pct: 0.02, params: {offset: 500}}
  - type: length_forge
    pct: 0.01
    params:
      new_len: 512
      pad_byte: "00"
      match:
        time_ranges: ["1700000000,1700000100"]
        ips: ["192.0.2.1"]
        ip_match: either
  - type: rate_adjust
    pct: 0.30
    params:
      shift_ms: 50
      max_delay_ms: 50
      match:
        time_ranges: ["1700000000,1700000100"]
        ips: ["192.0.2.1"]
        ip_match: either
```

---

## Execution Flow (Pipeline)

1. **Streaming Read**

   * Reads classic pcap records as `(timestamp, packet_bytes)`.

2. **Stage Pipeline**

   * Each plan item compiles into one or more stages.
   * Records flow through stages; each stage may drop, duplicate, rewrite bytes, or buffer/reorder.

3. **Streaming Write**

   * Writes output records via `dpkt.pcap.Writer`.

### Performance Notes

* Record-level operations (`loss`, `retransmit`, `reorder`, `length_forge`, `rate_adjust`) are bytes-first and fast.
* Content-modifying operations (`seq_offset`) cost more due to header touch + checksum recalculation.
* Increasing `chunk_size` can improve throughput by reducing Python overhead; typical 5k–20k is reasonable.

---

## Configuration Suggestions

### Network anomaly simulation

```json
[
  {"type": "loss", "pct": 0.05, "params": {}},
  {"type": "retransmit", "pct": 0.03, "params": {"copies": 1, "delay_ms": 0}},
  {"type": "reorder", "pct": 0.02, "params": {"k": 10, "ts_mode": "keep"}},
  {
    "type": "rate_adjust",
    "pct": 0.30,
    "params": {
      "shift_ms": 50,
      "max_delay_ms": 50,
      "match": {"time_ranges": ["1700000000,1700000100"], "ips": ["192.0.2.1"], "ip_match": "either"}
    }
  }
]
```

### Protocol testing

```json
[
  {"type": "seq_offset", "pct": 0.1, "params": {"offset": 1000}},
  {"type": "length_forge", "pct": 0.05, "params": {"new_len": 1500, "pad_byte": "00"}}
]
```

### Stress testing

```json
[
  {"type": "loss", "pct": 0.2, "params": {}},
  {"type": "retransmit", "pct": 0.15, "params": {"copies": 1}},
  {"type": "length_forge", "pct": 0.1, "params": {"new_len": 2048, "pad_byte": "00"}}
]
```

---

## Notes / Caveats

1. **Order matters**: disturbances run sequentially.
2. **Percentages stack**: multiple disturbances may apply to the same packet.
3. **Length forgery can create malformed packets**: downstream flow tools may drop/ignore such packets.
4. **Determinism**: same plan + same seed + same input path → deterministic output.
   Stage RNGs are derived independently to avoid cross-stage coupling.
5. **Rate adjustment is forward-only**: `rate_adjust` assumes timestamps shift forward by at most `max_delay_ms`.
   If you need arbitrary (forward/backward) shifts or large reordering, implement an external-sort based stage.