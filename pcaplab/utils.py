from pathlib import Path
import logging, json, os, re
from datetime import datetime
from __future__ import annotations
import atexit
import logging
import os
import queue
import sys
from logging.handlers import QueueHandler, QueueListener, TimedRotatingFileHandler
from pathlib import Path
from typing import Optional, Union


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

__all__ = ["setup", "get_logger", "log"]

# ---- internal globals ----
_log_name = "pcaplab"
log = logging.getLogger(_log_name)
log.addHandler(logging.NullHandler())
log.setLevel(logging.INFO)
log.propagate = False

_q: Optional[queue.Queue] = None
_listener: Optional[QueueListener] = None
_configured = False

def setup(
    log_dir: Optional[Union[str, os.PathLike]] = "logs",
    level: Union[int, str] = "INFO",
    console: bool = True,
    filename: str = "pcaplab.log",
    rotate_when: str = "midnight",
    rotate_backup: int = 7,
    encoding: str = "utf-8",
) -> logging.Logger:
    """
    Configure async logging. Call once at program start (e.g., in main).
    - log_dir=None 只打到控制台；给目录则写文件并按天轮转，保留 rotate_backup 份。
    - level 可用 "DEBUG"/"INFO"/"WARNING"/"ERROR".
    """
    global _q, _listener, _configured

    if _configured:
        return log  # idempotent

    # Normalize level
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    log.setLevel(level)

    # Formatter：精简但信息全；不做昂贵处理
    fmt = "[%(asctime)s] %(levelname).1s %(process)d %(threadName)s %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)

    # Build real handlers (sink side)
    handlers = []
    if console:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(formatter)
        h.setLevel(level)
        handlers.append(h)

    if log_dir is not None:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        file_handler = TimedRotatingFileHandler(
            filename=str(log_path / filename),
            when=rotate_when,
            backupCount=rotate_backup,
            encoding=encoding,
            utc=False,
            delay=True,  # 延迟打开文件，减少启动时 I/O
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        handlers.append(file_handler)

    # Queue pipeline (source side handler is cheap; I/O 在线程里)
    _q = queue.SimpleQueue()
    qh = QueueHandler(_q)
    qh.setLevel(level)

    # Clear possible placeholder handlers and attach queue handler
    _clear_handlers(log)
    log.addHandler(qh)

    # Start listener
    _listener = QueueListener(_q, *handlers, respect_handler_level=True)
    _listener.start()
    atexit.register(_shutdown_listener)

    _configured = True
    return log


def _clear_handlers(logger: logging.Logger) -> None:
    for h in list(logger.handlers):
        try:
            logger.removeHandler(h)
            h.close()
        except Exception:
            pass


def _shutdown_listener() -> None:
    global _listener
    if _listener:
        try:
            _listener.stop()
        except Exception:
            pass
        _listener = None


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a child logger: get_logger("pipeline") -> pcaplab.pipeline
    """
    if not name:
        return log
    lg = logging.getLogger(f"{_log_name}.{name}")
    lg.propagate = False
    if not lg.handlers and _configured:
        # Child loggers also emit into the queue via parent
        pass
    return lg

setup(log_dir="logs", level="INFO", console=True)
