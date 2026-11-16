"""Scan-history persistence in Postgres (the 'History Of Actions' indicator).

Entirely best-effort and optional: if DATABASE_URL is unset (local dev, tests,
offline triage) or the database is unreachable, every function degrades to a
no-op / empty result and NEVER raises into the request path. The scorer works
with or without a database.
"""
import json
import os
import threading

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:  # driver not installed in some environments — stay optional
    psycopg2 = None

_LOCK = threading.Lock()
_CONN = None

_DDL = """
CREATE TABLE IF NOT EXISTS scan_history (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    subject       TEXT,
    sender        TEXT,
    score         INTEGER,
    verdict       TEXT,
    verdict_label TEXT,
    explanation   TEXT,
    signals       JSONB
);
"""


def _enabled() -> bool:
    return bool(psycopg2 and os.environ.get("DATABASE_URL"))


def _connection():
    global _CONN
    if _CONN is None or getattr(_CONN, "closed", 1):
        _CONN = psycopg2.connect(os.environ["DATABASE_URL"], connect_timeout=5)
        _CONN.autocommit = True
        with _CONN.cursor() as cur:
            cur.execute(_DDL)
    return _CONN


def _reset():
    global _CONN
    try:
        if _CONN is not None:
            _CONN.close()
    except Exception:
        pass
    _CONN = None


def record_scan(subject, sender, score, verdict, verdict_label, explanation, signals):
    """Insert one scan. Safe to call from a background thread; never raises."""
    if not _enabled():
        return
    try:
        with _LOCK:
            with _connection().cursor() as cur:
                cur.execute(
                    """INSERT INTO scan_history
                       (subject, sender, score, verdict, verdict_label, explanation, signals)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (
                        (subject or "")[:500] or None,
                        (sender or "")[:320] or None,
                        score,
                        verdict,
                        verdict_label,
                        (explanation or "")[:1000] or None,
                        json.dumps(signals or []),
                    ),
                )
    except Exception as exc:
        print(f"[history] insert failed: {exc}")
        _reset()


def recent_scans(limit: int = 50) -> list[dict]:
    """Return the most recent scans (newest first). Empty list if unavailable."""
    if not _enabled():
        return []
    try:
        with _LOCK:
            with _connection().cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """SELECT id, created_at, subject, sender, score, verdict, verdict_label
                       FROM scan_history ORDER BY id DESC LIMIT %s""",
                    (max(1, min(limit, 200)),),
                )
                rows = cur.fetchall()
        for r in rows:
            r["created_at"] = r["created_at"].isoformat()
        return rows
    except Exception as exc:
        print(f"[history] query failed: {exc}")
        _reset()
        return []
