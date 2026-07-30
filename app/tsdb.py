import json
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from app.config import TSDB_DATA_FILE

logger = logging.getLogger(__name__)

class TimeSeriesDB:
    """High-performance, thread-safe in-memory time-series telemetry engine with bounded retention & disk persistence."""
    def __init__(self, max_points_per_series: int = 1440):
        self.max_points = max_points_per_series
        self._series: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self.load_from_disk()

    def load_from_disk(self):
        """Restore historical telemetry points from persistent disk storage."""
        if TSDB_DATA_FILE.exists():
            try:
                content = TSDB_DATA_FILE.read_text(encoding="utf-8")
                data = json.loads(content)
                if isinstance(data, dict):
                    with self._lock:
                        self._series = data
                    logger.info("Loaded TSDB telemetry history (%d series) from %s", len(self._series), TSDB_DATA_FILE)
            except Exception as e:
                logger.warning("Failed to load TSDB history from disk: %s", e)

    def save_to_disk(self):
        """Persist current telemetry series buffer to disk file."""
        try:
            with self._lock:
                snapshot = {k: v[-self.max_points:] for k, v in self._series.items()}
            TSDB_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
            TSDB_DATA_FILE.write_text(json.dumps(snapshot), encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to persist TSDB snapshot to disk: %s", e)

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

        # Trigger disk snapshot every 5 samples for global series
        if series_id == "global" and len(buf) % 5 == 0:
            self.save_to_disk()

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
            if len(valid) > 1:
                diffs = [abs(valid[i] - valid[i-1]) for i in range(1, len(valid))]
                jitter = sum(diffs) / len(diffs)
            else:
                jitter = 0.0
            loss_pct = round(((len(buf) - len(valid)) / len(buf)) * 100, 1) if buf else 0.0
            return {
                "cur": round(cur, 1), "avg": round(avg, 1), "min": round(mn, 1),
                "max": round(mx, 1), "p50": round(p50, 1), "p95": round(p95, 1),
                "p99": round(p99, 1), "jitter": round(jitter, 1), "loss": loss_pct,
                "samples_count": len(valid), "total_samples": len(buf)
            }

# Singleton instance
tsdb = TimeSeriesDB()
