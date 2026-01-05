#!/usr/bin/env bash
set -euo pipefail

# ----------------------------
# Config (override via env)
# ----------------------------
PCAP_INPUT_DEFAULT="/mnt/raid/luohaoran/cicids2018/Original Network Traffic and Log data"
OUT_BASE_DEFAULT="/mnt/raid/luohaoran/cicids2018/SaP/data/_pcaplab_smoke"
BACKEND_DEFAULT="processes"
WORKERS_DEFAULT=4
CHUNK_SIZE_DEFAULT=5000
LIMIT_DEFAULT=0

PCAP_INPUT="${PCAP_INPUT:-$PCAP_INPUT_DEFAULT}"
OUT_BASE="${OUT_BASE:-$OUT_BASE_DEFAULT}"
PCAPLAB_BACKEND="${PCAPLAB_BACKEND:-$BACKEND_DEFAULT}"
WORKERS="${WORKERS:-$WORKERS_DEFAULT}"
CHUNK_SIZE="${CHUNK_SIZE:-$CHUNK_SIZE_DEFAULT}"
LIMIT="${LIMIT:-$LIMIT_DEFAULT}"

# You MUST pass a plan file (same as pipeline uses)
if [ $# -lt 1 ]; then
  echo "Usage: $0 /path/to/plan.json"
  echo
  echo "Optional env overrides:"
  echo "  PCAP_INPUT=... OUT_BASE=... PCAPLAB_BACKEND=... WORKERS=... CHUNK_SIZE=... LIMIT=..."
  exit 2
fi
PLAN_FILE="$1"
if [ ! -f "$PLAN_FILE" ]; then
  echo "ERROR: PLAN_FILE not found: $PLAN_FILE"
  exit 2
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1"; exit 3; }; }
need pcaplab
need python

timestamp() { date +"%F %T"; }

dump_env_snapshot() {
  cat <<EOF
[$(timestamp)] [ENV SNAPSHOT]
PWD=$(pwd)
USER=${USER-}
HOSTNAME=${HOSTNAME-}
SHELL=${SHELL-}
PATH=${PATH-}

PCAP_INPUT=${PCAP_INPUT}
PLAN_FILE=${PLAN_FILE}
OUT_BASE=${OUT_BASE}

PCAPLAB_BACKEND=${PCAPLAB_BACKEND}
WORKERS=${WORKERS}
CHUNK_SIZE=${CHUNK_SIZE}
LIMIT=${LIMIT}

PCAPLAB=$(command -v pcaplab || true)
PCAPLAB_VERSION=$(pcaplab --version 2>&1 || true)
PYTHON=$(command -v python || true)
PYTHON_VERSION=$(python -V 2>&1 || true)
EOF
}

# ----------------------------
# Pick ONE pcap directory
# ----------------------------
echo "[$(timestamp)] Selecting a pcap directory under:"
echo "  ${PCAP_INPUT}"

# Prefer ".../pcap" directories; fallback to any directory containing *.pcap
PCAP_DIR="$(
  find "$PCAP_INPUT" -type d -name pcap -print 2>/dev/null | head -n 1 || true
)"
if [ -z "$PCAP_DIR" ]; then
  PCAP_FILE="$(
    find "$PCAP_INPUT" -type f -name "*.pcap" -print 2>/dev/null | head -n 1 || true
  )"
  if [ -z "$PCAP_FILE" ]; then
    echo "ERROR: No .pcap files found under: $PCAP_INPUT"
    exit 4
  fi
  PCAP_DIR="$(dirname "$PCAP_FILE")"
fi

# quick sanity: count pcaps
PCAP_COUNT="$(find "$PCAP_DIR" -maxdepth 1 -type f -name "*.pcap" | wc -l | tr -d ' ')"
echo "[$(timestamp)] Using PCAP_DIR:"
echo "  ${PCAP_DIR}"
echo "[$(timestamp)] PCAP count in dir (maxdepth=1): ${PCAP_COUNT}"

# ----------------------------
# Run pcaplab (single run)
# ----------------------------
RUN_ID="$(date +%Y%m%d_%H%M%S)_$$"
OUT_ROOT="${OUT_BASE}/run_${RUN_ID}"
LOG_DIR="${OUT_ROOT}/logs"
mkdir -p "$LOG_DIR"

CMD_LOG="${LOG_DIR}/pcaplab_cmd.log"
OUT_LOG="${LOG_DIR}/pcaplab_stdout_stderr.log"
ERR_LOG="${LOG_DIR}/detected_errors.log"
ENV_LOG="${LOG_DIR}/env_snapshot.log"

dump_env_snapshot | tee "$ENV_LOG" >/dev/null

PCAPLAB_CMD=(
  pcaplab
  --in-root  "$PCAP_DIR"
  --out-root "$OUT_ROOT"
  --backend  "$PCAPLAB_BACKEND"
  --workers  "$WORKERS"
  --chunk-size "$CHUNK_SIZE"
  --plan     "$PLAN_FILE"
  --limit    "$LIMIT"
)

echo "[$(timestamp)] pcaplab command:" | tee "$CMD_LOG" >/dev/null
{ printf '%q ' "${PCAPLAB_CMD[@]}"; echo; } | tee -a "$CMD_LOG" >/dev/null

echo "[$(timestamp)] Running pcaplab..."
set +e
"${PCAPLAB_CMD[@]}" 2>&1 | tee "$OUT_LOG"
rc=${PIPESTATUS[0]}
set -e

echo "[$(timestamp)] pcaplab exit code: ${rc}"
echo "[$(timestamp)] Logs:"
echo "  CMD_LOG = $CMD_LOG"
echo "  OUT_LOG = $OUT_LOG"
echo "  ENV_LOG = $ENV_LOG"
echo "  OUT_ROOT= $OUT_ROOT"

# ----------------------------
# Detect the specific YAML error (even if rc==0)
# ----------------------------
# Your observed signature:
# expected '<document start>', but found '<scalar>'
#   in "/mnt/.../label_flows_from_yaml.py", line 15, column 1
PATTERN_1="expected '<document start>', but found '<scalar>'"
PATTERN_2="label_flows_from_yaml.py"

if grep -q "$PATTERN_1" "$OUT_LOG" || grep -q "$PATTERN_2" "$OUT_LOG" || grep -q "pcaplab: \[FAIL\]" "$OUT_LOG"; then
  {
    echo "========================================"
    echo "[$(timestamp)] [DETECTED] pcaplab internal failure signature in output"
    echo "PCAP_DIR=${PCAP_DIR}"
    echo "OUT_ROOT=${OUT_ROOT}"
    echo "----------------------------------------"
    echo "[context] first 100 matches with surrounding lines:"
    grep -n -m 100 -C 2 -E "pcaplab: \\[FAIL\\]|expected '<document start>'|label_flows_from_yaml.py" "$OUT_LOG" || true
    echo "========================================"
  } | tee "$ERR_LOG" >/dev/null

  echo "[$(timestamp)] ERROR detected. See: $ERR_LOG"
  exit 10
fi

# If pcaplab itself returned non-zero, also fail
if [ $rc -ne 0 ]; then
  echo "[$(timestamp)] ERROR: pcaplab exited non-zero (rc=$rc). See: $OUT_LOG"
  exit $rc
fi

echo "[$(timestamp)] OK: pcaplab finished without detected FAIL signatures."
exit 0
