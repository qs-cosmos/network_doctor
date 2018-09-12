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
        if len(ipv4) < 20:
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


class ICMP(object):
    """ ICMP-网际控制报文 """
    def __init__(self):
        """ 默认初始化一个 ID 为0的 回送请求报文 """
        self.format = '!bbHHH'
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

    def json(self):
        return {
            'type': self.type,
            'code': self.code,
            'chk_sum': self.chk_sum,
            'id': self.id,
            'seq': self.seq,
            'data': self.data
        }


class UDP(object):
    pass


class TCP(object):
    pass


class DNS(object):
    """ DNS 报文 """

    def __init__(self):
        self.header_format = '!HHHHHH'
        self.construct()

    def construct(self, domain=None, ID=0, Flag=256, Qa=1, An=0, Au=0, Ad=0):
        """ 构建一个DNS查询报文(一次只查询一个域名)

        @param domain: 域名
        @type  domain: string

        @param ID: 会话标识
        @type  ID: int

        @param Flags: 标识
        @type  Flags: int

        @param Qa: Question Amount
        @type  Qa: int

        @param An: Answer RR Amount
        @type  An: int

        @param Au: Authority RR Amount
        @type  Au: int

        @param Ad: Additional RR Amount
        @type  Ad: int

        @return: 二进制DNS查询报文
        @rtype : string
        """
        self.id = ID
        self.flag = Flag
        self.qa = Qa
        self.an = An
        self.au = Au
        self.ad = Ad
        # 构建 dns 头部
        header = struct.pack(self.header_format, self.id, self.flag,
                                 self.qa, self.an, self.au, self.ad)
        # 构建问题区域
        from config.dns import Question
        self.question = Question()
        self.question.construct(domain)

        return header + self.question.question

    def analysis(self, packet):
        """ DNS 回答报文解析

        @param packet: 二进制DNS回答报文
        @type  packet: string
        """
        if len(packet) < 12:
            return False
        # 解析 dns 头部
        offset = 12
        self.id, self.flag, self.qa, self.an, self.au, self.ad = struct.unpack(
            self.header_format, packet[0:offset]
        )
        # 解析 问题区域
        from config.dns import Question
        self.question = Question()
        offset = self.question.analysis(packet, offset)
        if offset == -1:
            return False
        # 解析 回答区域
        from config.dns import Resource
        self.answers = []
        for i in range(self.an):
            answer = Resource()
            offset = answer.analysis(packet, offset)
            self.answers.append(answer)
        # 解析 权威区域

        # 解析 附加信息

        return True
