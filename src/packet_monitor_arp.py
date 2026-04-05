"""Shared ARP packet builders for packet monitor."""
from typing import Any, Optional

from src.types import IPv4Address, MACAddress


def build_arp_packet(
    ether_cls: Any,
    dot1q_cls: Any,
    arp_cls: Any,
    op: int,
    src_mac: str,
    src_ip: str,
    dst_mac: str,
    dst_ip: str,
    vlan: Optional[int],
) -> bytes:
    """Build ARP packet bytes (op 1=request, 2=reply)."""
    pkt = ether_cls(dst=dst_mac, src=src_mac)
    if dot1q_cls and vlan is not None:
        pkt = pkt / dot1q_cls(vlan=vlan)
    pkt = pkt / arp_cls(op=op, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip)
    return bytes(pkt)


def build_arp_reply_packet(
    ether_cls: Any,
    dot1q_cls: Any,
    arp_cls: Any,
    pkt: Any,
    reply_mac: MACAddress,
    requested_ip: IPv4Address,
    reply_vlan: Optional[int],
) -> tuple[bytes, Optional[int]]:
    """Build ARP reply packet bytes from request pkt; return (raw_bytes, vlan_id)."""
    req_mac = (pkt[ether_cls].src or getattr(pkt[arp_cls], "hwsrc", None)) or ""
    req_ip = str(pkt[arp_cls].psrc) if getattr(pkt[arp_cls], "psrc", None) else ""
    vid = reply_vlan
    if vid is None and dot1q_cls and dot1q_cls in pkt:
        try:
            vid = int(pkt[dot1q_cls].vlan)
        except (AttributeError, TypeError, ValueError):
            vid = None
    raw = build_arp_packet(
        ether_cls,
        dot1q_cls,
        arp_cls,
        2,
        str(reply_mac),
        str(requested_ip),
        req_mac,
        req_ip,
        vid,
    )
    return raw, vid
