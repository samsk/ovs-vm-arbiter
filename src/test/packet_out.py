"""Tests for src.packet_out."""
import logging
from src.types import BridgeName, OFPort
from src.packet_out import PacketOutRequest, AsyncPacketSender
from src.test import _test_assert


def test_packet_out_request() -> None:
    """PacketOutRequest: dataclass."""
    req = PacketOutRequest(bridge=BridgeName("vmbr0"), packet_bytes=b"\x00\x01", in_port=OFPort("1"))
    _test_assert(req.actions == "output:NORMAL", "default actions")


def test_async_packet_sender_enqueue() -> None:
    """AsyncPacketSender: enqueue (no worker)."""
    log = logging.getLogger("test")
    sender = AsyncPacketSender(log, max_queue=2)
    req = PacketOutRequest(bridge=BridgeName("vmbr0"), packet_bytes=b"\x00", in_port=OFPort("1"))
    _test_assert(sender.enqueue(req) is True, "enqueue")
    _test_assert(sender.enqueue(req) is True, "enqueue 2nd")
    _test_assert(sender.enqueue(req) is False, "queue full")


def test_packet_out_request_custom_actions() -> None:
    """PacketOutRequest: custom actions."""
    req = PacketOutRequest(
        bridge=BridgeName("vmbr0"), packet_bytes=b"\x00", in_port=OFPort("5"),
        actions="output:LOCAL,output:5",
    )
    _test_assert(req.actions == "output:LOCAL,output:5", "custom actions")
