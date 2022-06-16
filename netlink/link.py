import logging
from typing import Dict

from . import NetlinkMessage
from .enums import IfrFlags, RtaType
from .structs import IFINFOMSG, RTATTR

logger = logging.getLogger(__name__)


class NetworkInterface:
    index: int
    flags: bytes
    attributes: Dict[int, bytes]

    def __init__(self, index: int, flags: bytes, attributes: Dict[int, bytes]) -> None:
        self.index = index
        self.flags = flags
        self.attributes = attributes

    @classmethod
    def from_message(cls, message: NetlinkMessage) -> "NetworkInterface":
        ptr: int = 0
        package = message.payload
        attributes: Dict[int, bytes] = {}
        ifi_family, ifi_type, ifi_index, ifi_flags, ifi_change = IFINFOMSG.unpack_from(
            package, ptr
        )

        ptr += IFINFOMSG.size
        while ptr < len(package):
            attr_len, attr_type = RTATTR.unpack_from(package, ptr)
            if attr_len == 0:
                break
            attr_data = package[ptr + RTATTR.size : ptr + attr_len]
            if attr_type in attributes:
                logger.error(f"Duplicated attribute: {attr_type}")
            else:
                attributes[attr_type] = attr_data
            ptr += attr_len
        return cls(index=ifi_index, flags=ifi_flags, attributes=attributes)

    def __str__(self) -> str:
        return f"{self.name}: UP: {self.is_up()} LOOPBACk: {self.is_loopback()}"

    @property
    def name(self):
        ifname = self.attributes.get(RtaType.IFLA_IFNAME)
        if ifname is None:
            logger.error(f"IFLA_IFNAME not found for index: {self.index}")
            return "unnamed"
        if ifname.endswith(b"\00"):
            ifname = ifname.strip(b"\00")
        else:
            logger.error(f"IFLA_IFNAME attr does not end with null-byte: {ifname}")
        return ifname.decode()

    def is_loopback(self):
        return bool(self.flags & IfrFlags.IFF_LOOPBACK)

    def is_up(self):
        return bool(self.flags & IfrFlags.IFF_UP)

    def is_running(self):
        return bool(self.flags & IfrFlags.IFF_LOOPBACK)
