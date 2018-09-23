# coding: utf-8

""" 定义 IP 数据报 """
import re
import struct
from config.constant import FILE


def regex(filename):
    regex_file = FILE.module(__file__) + filename
    with open(regex_file, 'r') as f:
        return re.compile(f.readline().strip())


class IPV(object):
    """ IP Version """
    ERROR = 0       # ip 格式错误
    IPV4 = 1        # ipv4
    IPV6 = 2        # ipv6

    IPV4_REGEX = regex('ipv4.regex')    # ipv4_regex
    IPV6_REGEX = regex('ipv6.regex')    # ipv6_regex

    @staticmethod
    def check(ip):
        """ 检查 ip 格式是否正确, 并区分ipv4/ipv6

        @param ip: ip
        @type  ip: string (ipv4/ipv6)

        @return: ip 的版本
        @rtype : IPV
        """
        if not isinstance(ip, str):
            return IPV.ERROR
        if re.match(IPV.IPV4_REGEX, ip) is not None:
            return IPV.IPV4
        if re.match(IPV.IPV6_REGEX, ip) is not None:
            return IPV.IPV6
        return IPV.ERROR


class IPV4(object):
    """ IPV4 数据报 """
    def __init__(self):
        self.basic_format = '!BBHHHBBH4B4B'
        self.version = 4            # 版本 (4 bit)
        self.header_length = 20     # 首部长度 (4 bit 单位: bytes)
        self.DS = 0                 # 区分服务 (8 bit)
        self.length = 20            # 总长度   (16 bit)
        self.id = 0                 # 标识符   (16 bit)
        self.FF = False             # 标志字段中的第一位 (1 bit)
        self.DF = False             # 中间位 DF (Don't Fragment) (1 bit)
        self.MF = False             # 最后一位 MF (More Fragment) (1 bit)
        self.offset = 0             # 片偏移 (13 bit)
        self.ttl = 0                # 生存时间 (8 bit)
        self.proto = 0              # 协议 (8 bit)
        self.chksum = 0             # 首部校验和 (16 bit)
        self.src = 0                # 源地址 (32 bit)
        self.dst = 0                # 目的地址 (32 bit)

    def analysis(self, ipv4):
        """ 解析ipv4数据报

        基本思路: 只解析 IP数据报 的前20个字节(header)
        """
        if ipv4 is None or len(ipv4) < 20:
            return False
        header = struct.unpack(self.basic_format, ipv4[0:20])
        self.version = header[0] >> 4
        self.header_length = (header[0] & 0xf) * 4
        self.DS = header[1]
        self.length = header[2]
        self.id = header[3]
        self.FF = bool(header[4] >> 15 & 0x1)
        self.MF = bool(header[4] >> 14 & 0x1)
        self.DF = bool(header[4] >> 13 & 0x1)
        self.offset = header[4] & 0x1fff
        self.ttl = header[5]
        self.proto = header[6]
        self.chksum = header[7]
        self.src = reduce(lambda x, y: str(x) + '.' + str(y), header[8:12])
        self.dst = reduce(lambda x, y: str(x) + '.' + str(y), header[12:16])
        return True
