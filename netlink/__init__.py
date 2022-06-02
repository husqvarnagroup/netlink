import asyncio
import contextlib
import itertools
import logging
import os
import socket
import struct
from typing import Dict, List, Optional

from netlink import attributes

logger = logging.getLogger(__name__)


NETLINK_ROUTE = 0
NETLINK_UNUSED = 1
NETLINK_USERSOCK = 2
NETLINK_FIREWALL = 3
NETLINK_SOCK_DIAG = 4
NETLINK_NFLOG = 5
NETLINK_XFRM = 6
NETLINK_SELINUX = 7
NETLINK_ISCSI = 8
NETLINK_AUDIT = 9
NETLINK_FIB_LOOKUP = 10
NETLINK_CONNECTOR = 11
NETLINK_NETFILTER = 12
NETLINK_IP6_FW = 13
NETLINK_DNRTMSG = 14
NETLINK_KOBJECT_UEVENT = 15
NETLINK_GENERIC = 16
NETLINK_SCSITRANSPORT = 18
NETLINK_ECRYPTFS = 19
NETLINK_RDMMA = 20
NETLINK_CRYPTO = 21
NETLINK_SMC = 22

NETLINK_INET_DIAG = NETLINK_SOCK_DIAG

NLM_F_REQUEST = 1
NLM_F_MULTI = 2
NLM_F_ACK = 4
NLM_F_ECHO = 8
NLM_F_DUMP_INTR = 16
NLM_F_DUMP_FILTERED = 32

NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_ATOMIC = 0x400
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

NLM_F_REPLACE = 0x100
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLM_F_APPEND = 0x800

NLM_F_NONREC = 0x100

NLM_F_CAPPED = 0x100
NLM_F_ACK_TLVS = 0x200

NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLMSG_OVERRUN = 4
NLMSG_MIN_TYPE = 16

NLMSGERR_ATTR_UNUSED = 0
NLMSGERR_ATTR_MSG = 1
NLMSGERR_ATTR_OFFS = 2
NLMSGERR_ATTR_COOKIE = 3
NLMSGERR_ATTR_POLICY = 4

NETLINK_ADD_MEMBERSHIP = 1
NETLINK_DROP_MEMBERSHIP = 2
NETLINK_PKTINFO = 3
NETLINK_BROADCAST_ERROR = 4
NETLINK_NO_ENOBUFS = 5
NETLINK_LISTEN_ALL_NSID = 8
NETLINK_LIST_MEMBERSHIPS = 9
NETLINK_CAP_ACK = 10
NETLINK_EXT_ACK = 11
NETLINK_GET_STRICT_CHK = 12

SOL_NETLINK = 270


ATTRIBUTES_ERROR = {
    NLMSGERR_ATTR_MSG: attributes.string(),
    NLMSGERR_ATTR_OFFS: attributes.u32(),
    NLMSGERR_ATTR_COOKIE: attributes.binary(),
    NLMSGERR_ATTR_POLICY: attributes.nested(attributes.ATTRIBUTES_POLICY_TYPE),
}


class NetlinkMessage:
    def __init__(self, type, flags, payload):
        self.type: int = type
        self.flags: int = flags
        self.payload: bytes = payload


class NetlinkSocket:
    def __init__(
        self,
        sock: socket.socket,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        queue_size=0,
    ):
        self.socket = sock
        self.socket.setblocking(False)
        self.pid = self.socket.getsockname()[0]
        if loop is None:
            loop = asyncio.get_event_loop()
        self.loop = loop

        self.sequence = itertools.count(1)
        self.pending: Dict[int, asyncio.Event] = {}
        self.replies: Dict[int, NetlinkMessage] = {}
        self.packets: Dict[int, List[NetlinkMessage]] = {}

        self.package_queue: asyncio.Queue[NetlinkMessage] = asyncio.Queue(queue_size)

    def __aenter__(self):
        return self

    def add_membership(self, id):
        self.socket.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, id)

    async def start(self):
        length: int
        type: int
        flags: int
        sequence: int

        while True:
            data = await self.loop.sock_recv(self.socket, 65536)
            while data:
                length, type, flags, sequence, _ = struct.unpack_from("IHHII", data)
                payload = data[16:length]

                message = NetlinkMessage(type, flags, payload)
                if type == NLMSG_ERROR or type == NLMSG_DONE:
                    if sequence in self.pending:
                        self.replies[sequence] = message
                        self.pending.pop(sequence).set()
                    else:
                        logger.warning("Received unexpected ack or error packet")
                if sequence == 0:
                    await self.package_queue.put(message)
                elif sequence in self.packets:
                    self.packets[sequence].append(message)
                else:
                    logger.warning(
                        f"Received packet with unexpected sequence: {sequence}"
                    )

                data = data[length:]

    async def send(self, data):
        await self.loop.sock_sendall(self.socket, data)

    async def receive(self):
        return await self.package_queue.get()

    async def request(self, type, payload=b"", flags=0, timeout=3) -> List[NetlinkMessage]:
        event = asyncio.Event()

        sequence = next(self.sequence)
        self.pending[sequence] = event
        self.packets[sequence] = []

        flags |= NLM_F_REQUEST | NLM_F_ACK

        length = 16 + len(payload)
        header = struct.pack("IHHII", length, type, flags, sequence, self.pid)
        await self.send(header + payload)

        try:
            await asyncio.wait_for(event.wait(), timeout)
        except TimeoutError as e:
            logger.error("No response in {timeout}s: {e}")

        response = self.replies.pop(sequence)
        if response.type == NLMSG_ERROR:
            code: int = struct.unpack_from("i", response.payload)[0]
            if code != 0:
                message = os.strerror(-code)
                if response.flags & NLM_F_ACK_TLVS:
                    attrs = attributes.decode(response.payload[20:], ATTRIBUTES_ERROR)
                    if NLMSGERR_ATTR_MSG in attrs:
                        message = f"{message}: {attrs[NLMSGERR_ATTR_MSG]}"
                raise OSError(-code, message)
        elif response.type != NLMSG_DONE:
            raise RuntimeError("Expected ack or error packet")

        return self.packets.pop(sequence)

    async def noop(self):
        await self.request(NLMSG_NOOP)


@contextlib.asynccontextmanager
async def connect(proto, loop: Optional[asyncio.AbstractEventLoop] = None):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, proto) as sock:
        sock.setsockopt(SOL_NETLINK, NETLINK_CAP_ACK, True)
        sock.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, True)

        sock.bind((os.getgid(), 0))
        netlink_socket = NetlinkSocket(sock, loop)
        task = asyncio.create_task(netlink_socket.start())
        yield netlink_socket
        if not task.done:
            task.cancel()
