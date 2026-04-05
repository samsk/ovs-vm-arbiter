# Flow cookie from /run/ovs-flow-registry
import fcntl
import logging
import os
from typing import Optional

from src.types import OVSCookie
from src.config import (
    REGISTRY_FILE,
    LOCK_FILE,
    SCRIPT_NAME,
    ROLE,
    COOKIE_BASE,
    COOKIE_STEP,
    COOKIE_FALLBACK,
)


class FlowRegistry:
    """Get or register cookie in /run/ovs-flow-registry."""

    def __init__(
        self,
        script: str = SCRIPT_NAME,
        role: str = ROLE,
        description: str = "",
        log: Optional[logging.Logger] = None,
    ) -> None:
        self.script = script
        self.role = role
        self.description = description
        self.log = log
        self._cookie: Optional[OVSCookie] = None
        try:
            self._cookie = self._read_or_register()
        except Exception as e:
            self._cookie = OVSCookie(COOKIE_FALLBACK)
            if self.log:
                self.log.warning("registry not working, using fallback cookie %s: %s", self._cookie, e)

    def get_cookie(self) -> Optional[OVSCookie]:
        return self._cookie if self._cookie else None

    def _read_registry(self) -> dict[OVSCookie, tuple[str, str, str]]:
        out: dict[OVSCookie, tuple[str, str, str]] = {}
        if not os.path.isfile(REGISTRY_FILE):
            return out
        with open(REGISTRY_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 2)
                if len(parts) < 2:
                    continue
                cookie, script_name = OVSCookie(parts[0]), parts[1]
                role_val = desc_val = ""
                if len(parts) > 2:
                    for pair in parts[2].split():
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            if k == "role":
                                role_val = v
                            elif k == "description":
                                desc_val = v.strip('"')
                out[cookie] = (script_name, role_val, desc_val)
        return out

    def _read_or_register(self) -> Optional[OVSCookie]:
        reg_dir = os.path.dirname(REGISTRY_FILE) or "."
        lock_dir = os.path.dirname(LOCK_FILE)
        if reg_dir and reg_dir != ".":
            os.makedirs(reg_dir, mode=0o755, exist_ok=True)
        if lock_dir and lock_dir != ".":
            try:
                os.makedirs(lock_dir, mode=0o755, exist_ok=True)
            except OSError:
                pass
        try:
            fd = open(LOCK_FILE, "w")
        except OSError as e:
            raise OSError(f"cannot open registry lock {LOCK_FILE}: {e}") from e
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            reg = self._read_registry()
            for cookie, (s, _, _) in reg.items():
                if s == self.script:
                    return cookie
            max_cookie = COOKIE_BASE - COOKIE_STEP
            for c in reg:
                try:
                    v = int(c, 16)
                    if v > max_cookie:
                        max_cookie = v
                except ValueError:
                    pass
            next_cookie = max_cookie + COOKIE_STEP
            cookie = OVSCookie(f"0x{next_cookie:08x}")
            line = f"{cookie} {self.script} role={self.role}"
            if self.description:
                line += f' description="{self.description}"'
            with open(REGISTRY_FILE, "a") as f:
                f.write(line + "\n")
            return cookie
        finally:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
            fd.close()
        return None
