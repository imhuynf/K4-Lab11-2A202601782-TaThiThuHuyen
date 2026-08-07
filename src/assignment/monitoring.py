"""
Assignment 11 — Monitoring & Alerts.
Tracks block rate, rate-limit hits, judge fail rate.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_METRICS_PATH = (
    Path(__file__).resolve().parents[2] / "outputs" / "metrics.json"
)

@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str

@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""
    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Các bộ đếm hệ thống
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def check_metrics(self) -> list[Alert]:
        """Tính toán tỷ lệ và kích hoạt cảnh báo nếu vượt ngưỡng."""
        self.alerts = []
        
        # 1. Kiểm tra tỷ lệ tin nhắn bị chặn (Block Rate)
        if self.total_requests > 0:
            block_rate = self.blocked_requests / self.total_requests
            if block_rate > self.block_rate_threshold:
                self.alerts.append(Alert(
                    metric="block_rate",
                    value=block_rate,
                    threshold=self.block_rate_threshold,
                    message=f"Tỷ lệ chặn tin nhắn vượt ngưỡng: {block_rate:.2f} > {self.block_rate_threshold:.2f}"
                ))
                
        # 2. Kiểm tra số lần dính giới hạn tần suất (Rate limit hits)
        if self.rate_limit_hits > self.rate_limit_hit_threshold:
            self.alerts.append(Alert(
                metric="rate_limit_hits",
                value=float(self.rate_limit_hits),
                threshold=float(self.rate_limit_hit_threshold),
                message=f"Số lần dính giới hạn tần suất quá cao: {self.rate_limit_hits} > {self.rate_limit_hit_threshold}"
            ))
            
        # 3. Kiểm tra tỷ lệ Trọng tài AI đánh giá không an toàn (Judge fail rate)
        if self.judge_checks > 0:
            judge_fail_rate = self.judge_fails / self.judge_checks
            if judge_fail_rate > self.judge_fail_rate_threshold:
                self.alerts.append(Alert(
                    metric="judge_fail_rate",
                    value=judge_fail_rate,
                    threshold=self.judge_fail_rate_threshold,
                    message=f"Tỷ lệ Trọng tài đánh giá UNSAFE quá cao: {judge_fail_rate:.2f} > {self.judge_fail_rate_threshold:.2f}"
                ))
                
        return self.alerts

    def export_json(self, filepath: str | Path = DEFAULT_METRICS_PATH):
        """Xuất chỉ số đo lường ra file JSON."""
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = self.snapshot()
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests if self.total_requests else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
