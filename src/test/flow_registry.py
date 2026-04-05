"""Tests for src.flow_registry."""
import logging
from src.flow_registry import FlowRegistry
from src.config import SCRIPT_NAME, ROLE
from src.test import _test_assert


def test_flow_registry() -> None:
    """FlowRegistry: init and get_cookie (uses real or fallback)."""
    reg = FlowRegistry(script=SCRIPT_NAME, role=ROLE, log=logging.getLogger("test"))
    cookie = reg.get_cookie()
    _test_assert(cookie is not None, "get_cookie returns value or fallback")
