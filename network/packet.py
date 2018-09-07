# coding: utf-8

import struct
from enum import Enum
from config.function import do_check_sum


class Proto(object):
    """ Protocol  Names"""
    ICMP = 'icmp'
    TCP = 'tcp'
    UDP = 'udp'


class IPV(Enum):
    """ IP Version """
    ERROR = 0   # ip 格式错误
    IPV4 = 1    # ipv4
    IPV6 = 2    # ipv6


class IP(object):
    pass


class ICMP(object):
    """ ICMP-网际控制报文 """
    def __init__(self):
        """ 默认初始化一个 ID 为0的 回送请求报文 """
        self.format = 'bbHHH'
        self.construct()

    def construct(self, Type=8, Code=0, ID=0, Seq=0, Data=''):
        """ 构建 ICMP 报文 """
        self.type = Type        # 类型(8 bit)
        self.code = Code        # 代码(8 bit)
        self.chk_sum = 0        # 检验和(16 bit, config时重新初始化为0)
        self.id = ID            # 标识符(16 bit)
        self.seq = Seq          # 序列号(16 bit)
        self.data = Data + 'Hello World!'

        # 构建 icmp_header
        icmp_header = struct.pack(self.format, self.type, self.code,
                                  self.chk_sum, self.id, self.seq)
        self.chk_sum = do_check_sum(icmp_header + self.data)
        icmp_header = struct.pack(self.format, self.type, self.code,
                                  self.chk_sum, self.id, self.seq)
        self.icmp = icmp_header + self.data
        return self.icmp

    def analysis(self, icmp):
        """ 解析 ICMP 报文 """
        if len(icmp) < 8:
            return False
        icmp_header = icmp[0:8]
        self.type, self.code, self.chk_sum, self.id, self.seq = struct.unpack(
            self.format, icmp_header
        )
        self.data = icmp[8:]
        return True
