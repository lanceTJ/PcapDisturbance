# PcabDisturbance

This is a high-performance streaming PCAP disturbance toolkit implementing Threat Model I/II:

* Packet loss, retransmission, TCP sequence offset
* Packet length forgery, (offline) packet-rate modification placeholder
* Streaming chunk-based processing for large PCAPs
* Directory batch runner, mirroring date/PCAP directory structure, skipping `encrypted_pcaps` directory

## Installation

```bash
pip install -e .
```

## Usage

### 1. Configuration Preparation

* Copy `config.example.yaml` to `config.yaml` and modify as needed.
* Key fields:

  * `in_root`: Input PCAP directory path (e.g., `/data/en-cic2018/pcapdata`).
  * `out_root`: Output directory for disturbed PCAPs (directory structure will be mirrored).
  * `backend`: Processing backend (`threads` or `processes`; threads are good for I/O-bound workloads, processes for CPU-bound).
  * `workers`: Number of concurrent workers (default 4, adjust based on your machine).
  * `chunk_size`: Number of packets per chunk (default 5000, optimized for large files).
  * `seed`: Random seed (default 42, ensures reproducibility).
  * `plan`: Disturbance plan list; each disturbance step will run sequentially.

### 2. Running the Tool

Run batch processing using the CLI:

```bash
pcaplab --in-root <input_dir> --out-root <output_dir> --backend threads --workers 4 --chunk-size 5000 --seed 42 --plan plan.json
```

* `--plan`: Specify a JSON plan file (or use quick flags such as `--loss 0.1`).
* Other quick flags (override the plan file):

  * `--loss <pct>`: Add packet loss (e.g., `--loss 0.1` drops 10% of packets).
  * `--retransmit <pct>`: Add retransmission (e.g., `--retransmit 0.05` duplicates 5% of packets).
  * `--seq-offset <pct:offset>`: Add sequence offset (e.g., `--seq-offset 0.02:500`).
  * `--length-forge <pct:newlen>`: Add length forgery (e.g., `--length-forge 0.01:512`).
* `--resume`: Skip files that already exist in output.
* `--verbose`: Show detailed logs.
* Example: processing the CICIDS2018 dataset and applying only reorder:

  ```bash
  pcaplab --in-root /data/cicids2018 --out-root /output/reordered --backend threads --workers 8 --chunk-size 10000 --seed 42 --plan reorder_plan.json
  ```

### 3. How to adjust config to apply different disturbance types with different parameters

Disturbances are defined in the `plan` array of `config.yaml`.
They are applied sequentially (the output of one becomes the input of the next).
Each element is a dictionary with:

* `type` (disturbance type)

* `pct` (application probability, float 0–1)

* `params` (optional parameter dict)

* **Adjustment steps**:

  1. Edit the `plan` array: add/remove/reorder items.
  2. Set `pct` to control the proportion of affected packets (e.g., 0.1 = 10%).
  3. Configure parameters under `params` (use `{}` if none).
  4. Note: order matters (e.g., loss before reorder applies reorder on the remaining packets); percentages can stack (same packet may get multiple disturbances); content-modifying types (e.g., seq_offset) reduce performance.
  5. Save and run the CLI, or specify `--plan <file>`.

* **Supported disturbance types and examples**:

##### 1. **Packet Loss (loss)**

* Function: randomly drops `pct` of packets.
* Adjustment: set `pct`; no params required.
* Example (drop 20%):

  ```yaml
  plan:
    - {type: loss, pct: 0.2, params: {}}
  ```

##### 2. **Retransmission (retransmit/retrans)**

* Function: duplicates `pct` of packets, simulating retransmission.
* Example (drop 10%, then retransmit 15% of the remaining packets):

  ```yaml
  plan:
    - {type: loss, pct: 0.1, params: {}}
    - {type: retransmit, pct: 0.15, params: {}}
  ```

##### 3. **Reorder / Jitter (reorder/jitter)**

* Function: randomly shuffles segments within a chunk while keeping timestamps increasing.
* Adjustment: `pct` controls trigger probability; `params.m` controls max segment length (default 5).
* Example:

  ```yaml
  plan:
    - {type: reorder, pct: 1.0, params: {m: 10}}
  ```

##### 4. **TCP Sequence Offset (seq_offset)**

* Function: modifies TCP sequence numbers and recalculates checksums.
* Example:

  ```yaml
  plan:
    - {type: seq_offset, pct: 0.02, params: {offset: 1000}}
  ```

##### 5. **Length Forgery (length_forge)**

* Function: modify payload length (pad if shorter, truncate if longer).

* Example:

  ```yaml
  plan:
    - {type: length_forge, pct: 0.01, params: {new_len: 1024, pad_byte: "00"}}
  ```

* **Full config example** (mixed disturbances):

  ```yaml
  in_root: /data/cicids2018
  out_root: /output/perturbed
  backend: threads
  workers: 8
  chunk_size: 10000
  seed: 42
  plan:
    - {type: loss, pct: 0.1, params: {}}
    - {type: retransmit, pct: 0.05, params: {}}
    - {type: reorder, pct: 1.0, params: {m: 10}}
    - {type: seq_offset, pct: 0.02, params: {offset: 500}}
    - {type: length_forge, pct: 0.01, params: {new_len: 512, pad_byte: "00"}}
  ```

### Execution Flow Description

##### 1. **Selection Phase** (`_select_indices`)

* Applies disturbances like `loss`, `retransmit`, `reorder` in sequence
* Index-only operations, no packet parsing
* Statistics are collected per disturbance type

##### 2. **Modification Phase** (`_process_chunk`)

* Parses packets only if required by content-modifying disturbances (`seq_offset`, `length_forge`)
* Zero-copy optimization: packets that don’t need modification are emitted directly

##### 3. **Performance Optimization**

* **Fast path**: no content modification → direct byte output
* **Lazy parsing**: parse only packets needing modification
* **Chunk processing**: improves throughput

### Configuration Suggestions

##### Network anomaly simulation

```json
[
  {"type": "loss", "pct": 0.05, "params": {}},
  {"type": "retransmit", "pct": 0.03, "params": {}},
  {"type": "reorder", "pct": 1.0, "params": {}}
]
```

##### Protocol testing

```json
[
  {"type": "seq_offset", "pct": 0.1, "params": {"offset": 1000}},
  {"type": "length_forge", "pct": 0.05, "params": {"new_len": 1500}}
]
```

##### Stress testing

```json
[
  {"type": "loss", "pct": 0.2, "params": {}},
  {"type": "retransmit", "pct": 0.15, "params": {}},
  {"type": "length_forge", "pct": 0.1, "params": {"new_len": 2048}}
]
```

### Notes

1. **Order matters**: disturbances run sequentially, and each step sees the output of the previous one.
2. **Percentages stack**: multiple disturbances may apply to the same packet.
3. **Performance impact**: content-modifying disturbances (e.g., `length_forge`) require parsing.
4. **Seed stability**: same config + same seed = deterministic output, useful for reproducible experiments.

This design provides flexible disturbance composition, enabling simulation of diverse network environments and attack scenarios.
