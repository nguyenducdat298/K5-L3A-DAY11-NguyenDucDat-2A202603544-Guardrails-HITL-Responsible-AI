"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}
        self._pending: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        key = request_id or user_id
        self._open[key] = time.perf_counter()
        self._pending[key] = {
            "timestamp": utc_now_iso(),
            "user_id": user_id,
            "input": text,
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        key = request_id or user_id
        start = self._open.pop(key, None)
        meta = self._pending.pop(key, None) or {}
        latency_ms = (
            round((time.perf_counter() - start) * 1000.0, 2)
            if start is not None
            else 0.0
        )
        entry = {
            "timestamp": meta.get("timestamp") or utc_now_iso(),
            "request_id": request_id,
            "user_id": user_id,
            "input": meta.get("input", ""),
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        target = Path(filepath or default_audit_log_path())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return str(target)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
