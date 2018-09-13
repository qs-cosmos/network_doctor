# coding: utf-8

"""
由于 socket.recvfrom() 方法接收的数据存在问题, 暂停解析 DNS 报文的工作
"""

import struct
from logger import Logger


def get_domain(packet, offset):
    """ 获取 DNS报文 中问题/资源段的域名

    @param packet: 以问题区域为开始的报文段
    @type  packet: string

    @param offset: 偏移量
    @type  offset: int

    @return: (报文中域名占用字节数, 域名)
    @rtype : (int, string)
    """
    logger = Logger.get()
    length = 0          # 总长度
    node = 0            # 每一段的长度
    domain = None       # 域名
    point = False       # 是否为指针
    first_skip = True   # 是否为第一次跳转

    def is_point(byte):
        """ 识别 偏移指针 """
        return (ord(byte) | 0x3f) == 0xff

    def skip(location):
        """ 指针跳转

        @param location: 表示偏移指针的两个字节
        @type  location: [byte, byte]
        """
        return (ord(location[0]) & 0x3f << 8) + (ord(location[1]) & 0xff)
    while True:
        if node == 0:
            if len(packet) <= offset:
                logger.debug('The offset %d bytes beyonds the' +
                             'length of packet %d bytes.' % (
                                 offset, len(packet)
                             ))
                return (-1, None)
            if is_point(packet[offset]):
                point = True
                offset = skip(packet[offset: offset + 2])
                logger.debug('The pointer jumps to %dth byte.' % (offset))
            node = struct.unpack('!B', packet[offset])[0]

            # 当识别为指针时, 则该段实际所占长度为 2 bytes
            # 可能会存在递归指针跳转, 实际所占长度为第一次跳转时的长度
            if point and first_skip:
                length = length + 2
                first_skip = False
                logger.debug('The 1th pointer jump occurred.')
            # 如果不是指针, 则加上每一段的长度
            if not point:
                length = length + node + 1
            offset = offset + 1
            if node == 0:
                logger.debug('Return —— length: %d, domain: %s' % (
                    length, domain
                ))
                return (length, domain)
            domain = '' if domain is None else domain + '.'
        else:
            if len(packet) <= offset:
                logger.debug('The offset %d bytes beyonds the ' +
                             'length of packet %d bytes.' % (
                                 offset, len(packet)
                             ))
                return (-1, None)
            domain = domain + struct.unpack('!s', packet[offset])[0]
            offset = offset + 1
            node = node - 1


class DNStatus(object):
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
    SOCK_ERROR = 12                 # 创建 socket 时出错


class QueryType(object):
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
    def __init__(self):
        self.logger = Logger.get()
        self.domain = None          # 域名(长度不定)
        self.Type = QueryType.A     # 查询类型 (16 bit)
        self.Class = 1              # 查询类 (16 bit)
        self.length = 0             # 问题区域的长度
        self.packet = None          # DNS 查询数据报

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
        if self.domain is None:
            return

        def pack(x):
            if len(x) == 0:
                return ''
            f = '!b' + str(len(x)) + 's'
            return struct.pack(f, len(x), x)

        nodes = map(pack, self.domain.split('.'))
        self.packet = reduce(lambda x, y: x + y, nodes) + \
                        struct.pack('!bHH', 0, self.Type, self.Class)
        self.length = len(self.packet)

    def analysis(self, packet, offset):
        """ 解析 DNS 报文问题区域

        @param packet: 以问题区域为开始的报文段
        @type  packet: string

        @param Offset: 偏移量
        @type  Offset: int

        @return: 下一个区域的起始偏移量
        @rtype : int
        """
        length, self.domain = get_domain(packet, offset)
        if self.domain is None:
            self.logger.info('Failed to get the domain in the question area.')
            return -1
        offset = offset + length
        self.Type, self.Class = struct.unpack('!HH', packet[offset:offset + 4])
        self.length = length + 4
        return offset + 4

    def json(self):
        return {
            'domain': self.domain,
            'Type': self.Type,
            'Class': self.Class,
            'size': self.length
        }


class Resource(object):
    """ DNS 回答报文资源记录区域 """

    def __init__(self):
        self.logger = Logger.get()
        self.domain = None
        self.Type = QueryType.A
        self.Class = 1
        self.ttl = 0
        self.data_length = 0
        self.data = None

    def analysis(self, packet, offset):
        """ 解析 DNS 回答报文资源记录区域

        @param packet: 以问题区域为开始的报文段
        @type  packet: string

        @param Offset: 偏移量
        @type  Offset: int

        @return: 下一个区域的起始偏移量
        @rtype : int
        """
        #  解析域名

        length, self.domain = get_domain(packet, offset)
        if self.domain is None:
            self.logger.warning('Failed to get the domain ' +
                                'in the resource area.')
            return -1
        offset = offset + length
        self.Type, self.Class, self.ttl, self.data_length = struct.unpack(
            '!HHIH', packet[offset:offset + 10]
        )
        offset = offset + 10
        if self.Type == QueryType.A:
            def pack(x, y):
                return str(x) + '.' + str(y)
            self.data = reduce(pack, struct.unpack(
                '!BBBB', packet[offset:offset + 4]
            ))
        elif self.Type == QueryType.CNAME:
            length, self.data = get_domain(packet, offset)

        return offset + self.data_length

    def json(self):
        return {
            'domain': self.domain,
            'Type': self.Type,
            'Class': self.Class,
            'ttl': self.ttl,
            'data_size': self.data_length,
            'data': self.data
        }
