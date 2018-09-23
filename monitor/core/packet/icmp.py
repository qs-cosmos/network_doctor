# coding: utf-8

import struct

from core.packet.base import do_check_sum
from config.logger import Logger


class TYPE(object):
    ECHO_REPLY = 0              # 回显回答
    UNREACHABLE = 3             # 不可达
    SOURCE_QUENCH = 4           # 拥塞控制
    ECHO_REQUEST = 8            # 回显请求
    ROUTE_NOTICE = 9            # 路由器通告
    ROUTE_FINE = 10             # 路由器发现
    TTL_EXPIRED = 11            # TTL 过期
    IP_HEADER_ERROR = 12        # IP 首部错误


class CODE(object):
    """ 仅在 TYPE.UNREACHABLE 时有意义, 默认为 NETWORK """
    NETWORK = 0                 # 目的网络不可达
    HOST = 1                    # 目的主机不可达
    PROTO = 2                   # 目的协议不可达
    PORT = 3                    # 目的端口不可达
    NETWORK_UNKNOWN = 6         # 目的网络未知
    HOST_UNKNOWN = 7            # 目的主机未知


class ICMP(object):
    """ ICMP-网际控制报文 """
    def __init__(self):
        """ 默认初始化一个 ID 为0的 回送请求报文 """
        self.format = '!bbHHH'
        self.type = 8           # 类型(8 bit)
        self.code = 0           # 代码(8 bit)
        self.chk_sum = 0        # 检验和(16 bit)
        self.id = 0             # 标识符(16 bit)
        self.seq = 0            # 序列号(16 bit)
        self.icmp = ''
        self.data = ''
        self.logger = Logger.get()

    def construct(self, Type=8, Code=0, ID=0, Seq=0, Data=''):
        """ 构建 ICMP 报文 """
        self.logger.info('Start to construct a icmp query packet.')
        self.type = Type
        self.code = Code
        self.chk_sum = 0
        self.id = ID
        self.seq = Seq
        self.data = Data + 'Hello World!'

        # 构建 icmp_header
        icmp_header = struct.pack(self.format, self.type, self.code,
                                  self.chk_sum, self.id, self.seq)
        self.chk_sum = do_check_sum(icmp_header + self.data)
        icmp_header = struct.pack(self.format, self.type, self.code,
                                  self.chk_sum, self.id, self.seq)
        self.icmp = icmp_header + self.data
        self.logger.info('Successfully construct a icmp query packet.')
        return self.icmp

    def analysis(self, icmp):
        """ 解析 ICMP 报文 """
        self.logger.info('Start to analysis the icmp echo reply packet.')
        if icmp is None or len(icmp) < 8:
            self.logger.warning('The length of packet is less than 8 bytes.')
            return False
        icmp_header = icmp[0:8]
        self.type, self.code, self.chk_sum, self.id, self.seq = struct.unpack(
            self.format, icmp_header
        )
        self.data = icmp[8:]
        self.logger.info('Successfully analysis the icmp echo reply packet.')
        return True
