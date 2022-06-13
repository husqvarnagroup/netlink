import logging
import socket
from dataclasses import dataclass
from typing import Dict, Optional

from . import NetlinkMessage
from .enums import AddressFamily, RtaType
from .structs import IFADDRMSG, RTATTR

logger = logging.getLogger(__name__)


@dataclass
class NetworkAddress:
    index: int
    prefixlen: int
    family: int
    flags: bytes
    scope: int
    attributes: Dict[int, bytes]
    message: NetlinkMessage

    @classmethod
    def from_message(cls, message: NetlinkMessage) -> "NetworkAddress":
        ptr: int = 0
        package = message.payload
        attributes: Dict[int, bytes] = {}
        (
            ifi_family,
            ifa_prefixlen,
            ifa_flags,
            ifa_scope,
            ifa_index,
        ) = IFADDRMSG.unpack_from(package, ptr)

        ptr += IFADDRMSG.size
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
        return cls(
            index=ifa_index,
            flags=ifa_flags,
            attributes=attributes,
            message=message,
            prefixlen=ifa_prefixlen,
            family=ifi_family,
            scope=ifa_scope,
        )

    @property
    def interface_name(self) -> Optional[str]:
        name = self.attributes.get(RtaType.IFLA_IFNAME)
        if name is None:
            return None
        return name.strip(b"\00").decode()

    @property
    def ipaddress(self) -> str:
        ip_bytes = self.attributes.get(RtaType.IFLA_ADDRESS)
        if ip_bytes is None:
            raise ValueError("NetworkAddress has no IFLA_ADDRESS attribute")
        if self.is_ipv4():
            return socket.inet_ntop(socket.AF_INET, ip_bytes)
        elif self.is_ipv6():
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            raise ValueError(
                f"Only AF_INET and AF_INET6 supported, got {AddressFamily(self.family).name}"
            )

    def is_ipv4(self):
        return self.family == AddressFamily.AF_INET

    def is_ipv6(self):
        return self.family == AddressFamily.AF_INET6

    def __repr__(self) -> str:
        try:
            ip = self.ipaddress
        except ValueError:
            ip = ""
        return f"{self.__class__.__name__}(interface={self.interface_name}, ip={ip})"
