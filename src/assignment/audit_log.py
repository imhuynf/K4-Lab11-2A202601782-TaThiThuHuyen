"""
Assignment 11 — Audit Log starter.
Records every interaction for forensics.
"""
from __future__ import annotations
import json
import os
import time
from datetime import datetime, timezone

class AuditLogPlugin:
    """Framework-agnostic audit logger."""
    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Lưu lại thông tin đầu vào và mốc thời gian bắt đầu xử lý."""
        key = request_id or user_id
        self._open[key] = time.time()
        self._open[f"{key}_text"] = text
        self._open[f"{key}_timestamp"] = datetime.now(timezone.utc).isoformat()

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Ghi nhận đầu ra, xác định lớp phòng thủ nào đã chặn và tính toán độ trễ (latency)."""
        key = request_id or user_id
        start_time = self._open.get(key, time.time())
        latency = time.time() - start_time
        
        input_text = self._open.get(f"{key}_text", "")
        start_iso = self._open.get(f"{key}_timestamp", datetime.now(timezone.utc).isoformat())
        
        log_entry = {
            "request_id": request_id or "unknown",
            "user_id": user_id,
            "timestamp": start_iso,
            "input": input_text,
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_seconds": latency,
        }
        self.logs.append(log_entry)
        
        # Dọn dẹp bộ nhớ đệm sau khi ghi nhận xong
        self._open.pop(key, None)
        self._open.pop(f"{key}_text", None)
        self._open.pop(f"{key}_timestamp", None)

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Xuất danh sách nhật ký ra đĩa cứng dưới định dạng JSON."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()