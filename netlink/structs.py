from struct import Struct

NLMSGHDR = Struct("IHHII")
IFINFOMSG = Struct("BHiII")
IFADDRMSG = Struct("BBBBI")
RTATTR = Struct("HH")
