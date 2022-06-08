from struct import Struct

HEADER = Struct("IHHII")
IFINFOMSG = Struct("BHiII")
IFADDRMSG = Struct("BBBBI")
RTATTR = Struct("HH")
