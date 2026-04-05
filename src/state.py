# Load/save state JSON
import json
import logging
import os
import time
from typing import Any, Optional

from src.config import STATE_FILE
from src.models import IPEntryStore

_LOG = logging.getLogger(__name__)


def load_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def save_json(path: str, data: Any) -> None:
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=0)
    except OSError as e:
        _LOG.warning("save_json failed path=%s error=%s", path, e)


class StateManager:
    """Persistence for IP entry state (central store)."""

    def __init__(self, state_dir: str) -> None:
        self.state_dir = state_dir
        self._path = os.path.join(state_dir, STATE_FILE)

    def load_into(
        self, store: IPEntryStore, max_age_sec: Optional[float] = None
    ) -> None:
        """Load state into store. If max_age_sec and file older, skip load and write fresh."""
        if max_age_sec and max_age_sec > 0 and os.path.exists(self._path):
            try:
                mtime = os.path.getmtime(self._path)
                if (time.time() - mtime) > max_age_sec:
                    self.save_from(store)
                    return
            except OSError:
                pass
        data = load_json(self._path)
        if data:
            store.load_from_dict(data)

    def save_from(self, store: IPEntryStore) -> None:
        os.makedirs(self.state_dir, mode=0o755, exist_ok=True)
        save_json(self._path, store.to_dict())
