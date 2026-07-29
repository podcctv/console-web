import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

class TimeSeriesDB:
    """High-performance, thread-safe in-memory time-series telemetry engine with bounded retention."""
    def __init__(self, max_points_per_series: int = 1440):
        self.max_points = max_points_per_series
        self._series: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def insert(self, series_id: str, timestamp: float, value: Optional[float], metadata: Optional[Dict[str, Any]] = None):
        with self._lock:
            if series_id not in self._series:
                self._series[series_id] = []
            buf = self._series[series_id]
            buf.append({
                "time": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S") if isinstance(timestamp, (int, float)) else str(timestamp),
                "timestamp": timestamp,
                "latency": value,
                "meta": metadata or {}
            })
            if len(buf) > self.max_points:
                buf.pop(0)

    def query(self, series_id: str = "global", limit: int = 60) -> List[Dict[str, Any]]:
        with self._lock:
            buf = self._series.get(series_id, [])
            return list(buf[-limit:])

    def get_stats(self, series_id: str = "global") -> Dict[str, Any]:
        with self._lock:
            buf = self._series.get(series_id, [])
            valid = [p["latency"] for p in buf if p.get("latency") is not None]
            if not valid:
                return {
                    "cur": None, "avg": None, "min": None, "max": None,
                    "p50": None, "p95": None, "p99": None, "jitter": 0.0,
                    "loss": 0.0, "samples_count": 0, "total_samples": len(buf)
                }
            sorted_v = sorted(valid)
            cur = valid[-1]
            avg = sum(valid) / len(valid)
            mn = sorted_v[0]
            mx = sorted_v[-1]
            p50 = sorted_v[int(len(sorted_v) * 0.50)]
            p95 = sorted_v[int(len(sorted_v) * 0.95)]
            p99 = sorted_v[min(len(sorted_v) - 1, int(len(sorted_v) * 0.99))]
            jitter = (mx - mn) / 2.0 if len(valid) > 1 else 0.0
            loss_pct = round(((len(buf) - len(valid)) / len(buf)) * 100, 1) if buf else 0.0
            return {
                "cur": round(cur, 1), "avg": round(avg, 1), "min": round(mn, 1),
                "max": round(mx, 1), "p50": round(p50, 1), "p95": round(p95, 1),
                "p99": round(p99, 1), "jitter": round(jitter, 1), "loss": loss_pct,
                "samples_count": len(valid), "total_samples": len(buf)
            }

# Singleton instance
tsdb = TimeSeriesDB()
