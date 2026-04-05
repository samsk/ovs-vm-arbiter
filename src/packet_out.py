# Async packet-out queue
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from src.types import BridgeName, OFPort
from src.ovs_cmd import OVSCommand


@dataclass
class PacketOutRequest:
    """Request to send packet via OVS packet-out."""
    bridge: BridgeName
    packet_bytes: bytes
    in_port: OFPort
    actions: str = "output:NORMAL"


class AsyncPacketSender:
    """Async worker to send packets via OVS packet-out."""

    def __init__(self, log: logging.Logger, max_queue: int = 1000) -> None:
        self._log = log
        self._queue: asyncio.Queue[PacketOutRequest] = asyncio.Queue(maxsize=max_queue)
        self._stop = False
        self._task: Optional[asyncio.Task[None]] = None

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._task = loop.create_task(self._worker())

    async def stop(self) -> None:
        self._stop = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def enqueue(self, req: PacketOutRequest) -> bool:
        try:
            self._queue.put_nowait(req)
            return True
        except asyncio.QueueFull:
            return False

    async def _worker(self) -> None:
        while not self._stop:
            try:
                req = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            asyncio.create_task(self._send_packet_task(req))

    async def _send_packet_task(self, req: PacketOutRequest) -> None:
        try:
            if not isinstance(req.packet_bytes, bytes) or len(req.packet_bytes) == 0:
                self._log.debug("packet-out skip: invalid packet_bytes")
                return
            spec_port = "LOCAL" if req.in_port == "65534" else req.in_port
            spec = f"in_port={spec_port},packet={req.packet_bytes.hex()},actions={req.actions}"
            ok, err = await OVSCommand.run_ofctl_async("packet-out", req.bridge, spec)
            if not ok:
                self._log.debug("packet-out failed: %s", err)
            else:
                self._log.debug("packet-out sent bridge=%s in_port=%s len=%d", req.bridge, req.in_port, len(req.packet_bytes))
        except Exception as e:
            self._log.debug("packet-out task error: %s", e)
