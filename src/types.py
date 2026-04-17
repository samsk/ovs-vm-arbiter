# Semantic type aliases and optional deps (pyroute2, scapy)
from __future__ import annotations

import os
from typing import Literal, NewType, Union

# Network identifiers
MACAddress = NewType("MACAddress", str)
IPv4Address = NewType("IPv4Address", str)
BridgeName = NewType("BridgeName", str)
InterfaceName = NewType("InterfaceName", str)
NodeID = NewType("NodeID", str)
VMID = NewType("VMID", str)

InstanceEntryType = Literal["qemu", "lxc", "vm"]
NonInstanceEntryType = Literal["bridge", "foreign"]
EntryType = Union[InstanceEntryType, NonInstanceEntryType]
UnmeshedEntryType = Literal["foreign"]
InstanceType = Literal["qemu", "lxc"]

SnoopOrigin = Literal["arp", "dhcp", "proxmox"]
OFPort = NewType("OFPort", str)
OVSCookie = NewType("OVSCookie", str)

try:
    from pyroute2 import IPRoute
except ImportError:
    IPRoute = None  # type: ignore[misc, assignment]

RT_SCOPE_HOST = 254

_SCAPY_BASE = "/var/lib/ovs-vm-arbiter"
if "XDG_CONFIG_HOME" not in os.environ:
    os.environ["XDG_CONFIG_HOME"] = os.path.join(_SCAPY_BASE, ".config")
if "XDG_CACHE_HOME" not in os.environ:
    os.environ["XDG_CACHE_HOME"] = os.path.join(_SCAPY_BASE, ".cache")

try:
    from scapy.all import Ether, ARP, UDP, BOOTP, DHCP, Dot1Q, sniff, sendp
except ImportError:
    sniff = None
    sendp = None
    Dot1Q = None
