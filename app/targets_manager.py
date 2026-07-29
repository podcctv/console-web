import json
import logging
from app.config import MONITOR_TARGETS_FILE, DEFAULT_TARGETS

logger = logging.getLogger(__name__)

def load_targets():
    if MONITOR_TARGETS_FILE.exists():
        try:
            return json.loads(MONITOR_TARGETS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return DEFAULT_TARGETS

def save_targets(targets):
    try:
        MONITOR_TARGETS_FILE.write_text(json.dumps(targets, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to save targets.json: %s", e)
