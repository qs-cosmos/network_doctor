# coding: utf-8

import struct

from enum import Enum


def get_domain(packet):
    """ 获取 DNS报文 中问题/资源段的域名

    @param packet: 以域名为开始的报文段
    @type  packet: string

    @return: (报文段中域名长度, 域名, 剩余报文段)
    @rtype : (int, string, string)
    """
    location = 0
    length = 0
    domain = None
    while True:
        if location == 0:
            location = struct.unpack('!b', packet[0])[0]
            packet = packet[1:]
            length = length + 1
            if location == 0:
                return (length, domain, packet)
            domain = '' if domain is None else domain + '.'
        else:
            domain = domain + struct.unpack('!s', packet[0])[0]
            packet = packet[1:]
            length = length + 1
            location = location - 1


class DNStatus(Enum):
    """ DNS 报文的状态码

    取值说明: [0, 9] => DNS RCODES, [10, ) => 自定义
    """
    NO_ERROR = 0                    # DNS 请求完成
    FORMERR = 1                     # DNS 请求格式错误
    SERVER_FAIL = 2                 # DNS 服务器错误
    NO_DOMAIN = 3                   # 域名不存在
    NO_TIMP = 4                     # 功能未实现
    REFUSED = 5                     # 服务器拒绝回答请求
    YX_DOMAIN = 6                   # 不应该存在的名称, 但确实存在
    XRREST = 7                      # 不应该存在的回答, 但确实存在
    NO_TAUTH = 8                    # DNS 服务器对该区域不具有权威性
    NO_TZONE = 9                    # 名称不在区域中
    NO_ANSWER = 10                  # 无回答
    TIME_OUT = 11                   # 超时


class QueryType(Enum):
    """ DNS 报文常用查询类型 """
    A = 1                           # 由域名获得IPv4地址
    NS = 2                          # 查询域名服务器
    CNAME = 5                       # 查询规范名称
    SOA = 6                         # 开始授权
    WKS = 11                        # 熟知服务
    PTR = 12                        # 把IP地址转换成域名
    HINFO = 13                      # 主机信息
    MX = 15                         # 邮件交换
    AAAA = 28                       # 由域名获得 IPV6 地址
    AXFR = 252                      # 传送整个区的请求
    ANY = 255                       # 对所有记录的请求


class Question(object):
    """ DNS 报文问题区域 —— Only One Question"""
    def construct(self, domain=None, Type=QueryType.A, Class=1):
        """ 构建 DNS 报文问题区域

        @param domain: 域名
        @type  domain: string

        @param Type: 查询类型
        @type  Type: QueryType

        @param Class: 查询类
        @type  Class: int

        @return: 问题区域二进制数据
        @rtype : string
        """
        self.domain = domain        # 域名(长度不定)
        self.Type = Type            # 查询类型 (16 bit)
        self.Class = Class          # 查询类 (16 bit)
        self.length = 0             # 问题区域的长度
        self.question = ''
        if self.domain is None:
            return

        def pack(x):
            if len(x) == 0:
                return ''
            f = '!b' + str(len(x)) + 's'
            return struct.pack(f, len(x), x)

        nodes = map(pack, self.domain.split('.'))
        self.question = reduce(lambda x, y: x + y, nodes) + \
                        struct.pack('!bHH', 0, self.Type.value, self.Class)
        self.length = len(self.question)

    def analysis(self, packet):
        """ 解析 DNS 报文问题区域

        @param packet: 以问题区域为开始的报文段
        @type  packet: string

        @return: 去除问题区域后的报文段
        @rtype : string
        """
        length, self.domain, packet = get_domain(packet)
        self.length = length + len(packet)
        self.Type, self.Class = struct.unpack('!HH', packet)
        return packet


class Resource(object):
    pass
