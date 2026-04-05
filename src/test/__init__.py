"""Test package: test/<module>.py per source module. Run via src.tests.run_tests() (--test)."""
from __future__ import annotations

from typing import Optional

from src.types import OVSCookie


def _test_assert(cond: bool, msg: str) -> None:
    """Raise AssertionError if cond is False."""
    if not cond:
        raise AssertionError(msg)


class _MockFlowRegistry:
    """Fake registry for tests (get_cookie returns 0x10000000)."""
    def get_cookie(self) -> Optional[OVSCookie]:
        return OVSCookie("0x10000000")


def run_tests() -> int:
    """Delegate to main test runner (merged suite in tests.py)."""
    from src.tests import run_tests as _run
    return _run()
