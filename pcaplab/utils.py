from pathlib import Path
import logging, json, os, re
from datetime import datetime

def setup_logger(name="pcaplab", level=logging.INFO):
    fmt = "%(asctime)s %(levelname)s: %(message)s"
    logging.basicConfig(level=level, format=fmt)
    return logging.getLogger(name)

log = setup_logger()

ENCRYPTED_DIR_RE = re.compile(r"^encrypted", re.I)

def is_encrypted_dir(p: Path) -> bool:
    return ENCRYPTED_DIR_RE.match(p.name or "") is not None

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def atomic_write_json(path: Path, obj: dict):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    tmp.replace(path)

def now_iso():
    return datetime.utcnow().isoformat() + "Z"
