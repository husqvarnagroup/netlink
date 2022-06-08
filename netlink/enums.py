import enum


class RtaType(enum.IntEnum):
    IFLA_UNSPEC = 0
    IFLA_ADDRESS = 1
    IFLA_BROADCAST = 2
    IFLA_IFNAME = 3
    IFLA_MTU = 4
    IFLA_LINK = 5
    IFLA_QDISC = 6
    IFLA_STATS = 7
    IFLA_COST = 8
    IFLA_PRIORITY = 9
    IFLA_MASTER = 10
    IFLA_WIRELESS = 11
    IFLA_PROTINFO = 12
    IFLA_TXQLEN = 13
    IFLA_MAP = 14
    IFLA_WEIGHT = 15
    IFLA_OPERSTATE = 16
    IFLA_LINKMODE = 17
    IFLA_LINKINFO = 18
    IFLA_NET_NS_PID = 19
    IFLA_IFALIAS = 20


class AddressFamily(enum.IntEnum):
    AF_UNSPEC = 0
    AF_UNIX = 1
    AF_LOCAL = 1
    AF_INET = 2
    AF_AX25 = 3
    AF_IPX = 4
    AF_APPLETALK = 5
    AF_NETROM = 6
    AF_BRIDGE = 7
    AF_ATMPVC = 8
    AF_X25 = 9
    AF_INET6 = 10
    AF_ROSE = 11
    AF_DECnet = 12
    AF_NETBEUI = 13
    AF_SECURITY = 14
    AF_KEY = 15
    AF_NETLINK = 16
    AF_ROUTE = 16
    AF_PACKET = 17
    AF_ASH = 18
    AF_ECONET = 19
    AF_ATMSVC = 20
    AF_RDS = 21
    AF_SNA = 22
    AF_IRDA = 23
    AF_PPPOX = 24
    AF_WANPIPE = 25
    AF_LLC = 26
    AF_CAN = 29
    AF_TIPC = 30
    AF_BLUETOOTH = 31
    AF_IUCV = 32
    AF_RXRPC = 33
    AF_ISDN = 34
    AF_PHONET = 35
    AF_IEEE802154 = 36
    AF_CAIF = 37
    AF_ALG = 38
    AF_NFC = 39
    AF_MAX = 40


class Types(enum.IntEnum):
    BASE = 16
    NEWLINK = 16
    DELLINK = 17
    GETLINK = 18
    SETLINK = 19
    NEWADDR = 20
    DELADDR = 21
    GETADDR = 22
    NEWROUTE = 24
    DELROUTE = 25
    GETROUTE = 26
    NEWNEIGH = 28
    DELNEIGH = 29
    GETNEIGH = 30
    NEWRULE = 32
    DELRULE = 33
    GETRULE = 34
    NEWQDISC = 36
    DELQDISC = 37
    GETQDISC = 38
    NEWTCLASS = 40
    DELTCLASS = 41
    GETTCLASS = 42
    NEWTFILTER = 44
    DELTFILTER = 45
    GETTFILTER = 46
    NEWACTION = 48
    DELACTION = 49
    GETACTION = 50
    NEWPREFIX = 52
    GETMULTICAST = 58
    GETANYCAST = 62
    NEWNEIGHTBL = 64
    GETNEIGHTBL = 66
    SETNEIGHTBL = 67
    NEWNDUSEROPT = 68
    NEWADDRLABEL = 72
    DELADDRLABEL = 73
    GETADDRLABEL = 74
    GETDCB = 78
    SETDCB = 79
    NEWNETCONF = 80
    GETNETCONF = 82
    NEWMDB = 84
    DELMDB = 85
    GETMDB = 86
    NEWNSID = 88
    DELNSID = 89
    GETNSID = 90


@enum.unique
class IfrFlags(enum.IntFlag):
    IFF_UP = 1
    IFF_BROADCAST = 2
    IFF_DEBUG = 4
    IFF_LOOPBACK = 8
    IFF_POINTOPOINT = 16
    IFF_RUNNING = 32
    IFF_NOARP = 64
    IFF_PROMISC = 128
    IFF_NOTRAILERS = 256
    IFF_ALLMULTI = 512
    IFF_MASTER = 1024
    IFF_SLAVE = 2048
    IFF_MULTICAST = 4096
    IFF_PORTSEL = 8192
    IFF_AUTOMEDIA = 16384
    IFF_DYNAMIC = 32768
    IFF_LOWER_UP = 65536
    IFF_DORMANT = 131072
    IFF_ECHO = 262144
