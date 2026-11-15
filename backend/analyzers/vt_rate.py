"""Shared VirusTotal throttle. Free API = 4 requests/min, shared by file and domain lookups.
VT_MIN_INTERVAL (seconds between calls) defaults to 0 so the live API stays fast;
triage.py sets it to 15 for batch runs."""
import os
import threading
import time

_lock = threading.Lock()
_last = 0.0


def wait_turn():
    global _last
    interval = float(os.environ.get("VT_MIN_INTERVAL", "0") or 0)
    if interval <= 0:
        return
    with _lock:
        delay = _last + interval - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        _last = time.monotonic()
