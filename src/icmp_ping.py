"""Native ICMP echo for ping-neighbours: send one echo request, no subprocess, no wait for reply.

Used by ArbiterCore._ping_neighbours_loop to ping mesh neighbour IPs from the host.
Requires CAP_NET_RAW. Payload optional (min 0 bytes).
"""
import socket
import struct
from typing import Optional

ICMP_ECHO = 8
ICMP_ECHO_CODE = 0


def raw_icmp_socket_ok() -> bool:
    """Return True when raw ICMP socket can be opened."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError:
        return False
    try:
        return True
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _icmp_checksum(data: bytes) -> int:
    """One's complement sum of 16-bit words; return 16-bit checksum."""
    n = len(data)
    if n & 1:
        data += b"\x00"
    acc = 0
    for i in range(0, n, 2):
        acc += (data[i] << 8) | data[i + 1]
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return ~acc & 0xFFFF


def send_icmp_echo(dest_ip: str, _sock: Optional[socket.socket] = None) -> None:
    """Send one ICMP echo request to dest_ip; no wait for reply. Caller may reuse sock."""
    payload = b"ovs-vm-arbiter"  # optional; min 0
    pid = 0
    seq = 0
    header = struct.pack("!BBHHH", ICMP_ECHO, ICMP_ECHO_CODE, 0, pid, seq)
    chk = _icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO, ICMP_ECHO_CODE, chk, pid, seq)
    packet = header + payload
    own = _sock is None
    if own:
        _sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        _sock.sendto(packet, (dest_ip, 0))
    finally:
        if own and _sock:
            try:
                _sock.close()
            except Exception:
                pass
